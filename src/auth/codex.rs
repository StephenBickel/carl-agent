use std::borrow::Cow;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use semver::VersionReq;
use serde_json::{Map, Value, json};
use url::Url;
use uuid::Uuid;

use super::{
    AuthError, AuthErrorCode, AuthFuture, AuthMethod, AuthState, AuthorizationUrl, LoginChallenge,
    SubscriptionAuthBroker, SubscriptionPlan, SubscriptionService, UserCode,
};
use crate::sidecar::{
    JsonlSidecar, NotificationPolicy, ProviderHome, SidecarCommand, SidecarError, SidecarErrorCode,
    SidecarLimits, TrustedExecutable, VersionOutputFormat,
};

const CODEX_VERSION: &str = "=0.136.0";
const KEYRING_CONFIG: &[u8] = b"cli_auth_credentials_store = \"keyring\"\n";
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIRMATION_READS: usize = 8;
const MAX_NOTIFICATIONS_PER_OPERATION: usize = 32;
const CODEX_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_OAUTH_SCOPE: &str =
    "openid profile email offline_access api.connectors.read api.connectors.invoke";

/// Logging out can affect another Codex CLI or IDE session for the same OS user because
/// OpenAI does not document OS-keyring records as isolated by `CODEX_HOME`.
pub const CODEX_LOGOUT_WARNING: &str =
    "Logging out can affect another Codex CLI or IDE session for this OS user.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodexAuthTimeouts {
    request: Duration,
    login: Duration,
    confirmation: Duration,
    retry_interval: Duration,
}

impl CodexAuthTimeouts {
    #[must_use]
    pub const fn new(
        request: Duration,
        login: Duration,
        confirmation: Duration,
        retry_interval: Duration,
    ) -> Self {
        Self {
            request,
            login,
            confirmation,
            retry_interval,
        }
    }

    fn validate(self) -> Result<Self, AuthError> {
        if self.request.is_zero()
            || self.request > MAX_REQUEST_TIMEOUT
            || self.login.is_zero()
            || self.login > MAX_LOGIN_TIMEOUT
            || self.confirmation.is_zero()
            || self.confirmation > MAX_CONFIRMATION_TIMEOUT
            || self.retry_interval.is_zero()
            || self.retry_interval > self.confirmation
        {
            return Err(protocol_mismatch());
        }
        Ok(self)
    }
}

impl Default for CodexAuthTimeouts {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(5),
            login: Duration::from_secs(10 * 60),
            confirmation: Duration::from_secs(10),
            retry_interval: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LoginId(Uuid);

impl LoginId {
    fn parse(value: &str) -> Result<Self, AuthError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| protocol_mismatch())
    }

    fn into_wire(self) -> String {
        self.0.hyphenated().to_string()
    }
}

impl fmt::Debug for LoginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginId(<redacted>)")
    }
}

#[derive(Clone, Copy)]
struct PendingLogin {
    id: LoginId,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct TerminalRecord {
    id: LoginId,
    success: bool,
}

#[derive(Clone, Copy)]
enum LoginLifecycle {
    Idle,
    AwaitingCompletion(PendingLogin),
    CompletedAwaitingReload(LoginId),
}

impl LoginLifecycle {
    fn login_id(self) -> Option<LoginId> {
        match self {
            Self::Idle => None,
            Self::AwaitingCompletion(pending) => Some(pending.id),
            Self::CompletedAwaitingReload(id) => Some(id),
        }
    }
}

struct NotificationOperation {
    deadline: Instant,
    consumed: usize,
}

impl NotificationOperation {
    fn for_duration(duration: Duration) -> Result<Self, AuthError> {
        Ok(Self {
            deadline: Instant::now()
                .checked_add(duration)
                .ok_or_else(protocol_mismatch)?,
            consumed: 0,
        })
    }

    fn with_deadline(deadline: Instant) -> Self {
        Self {
            deadline,
            consumed: 0,
        }
    }

    fn reset_deadline(&mut self, duration: Duration) -> Result<(), AuthError> {
        self.deadline = Instant::now()
            .checked_add(duration)
            .ok_or_else(protocol_mismatch)?;
        Ok(())
    }

    fn check_deadline(&self) -> Result<(), AuthError> {
        remaining(self.deadline).map(|_| ())
    }

    fn remaining(&self) -> Result<Duration, AuthError> {
        remaining(self.deadline)
    }

    fn consume_notification(&mut self) -> Result<(), AuthError> {
        self.check_deadline()?;
        self.consumed = self.consumed.checked_add(1).ok_or_else(protocol_mismatch)?;
        if self.consumed > MAX_NOTIFICATIONS_PER_OPERATION {
            return Err(protocol_mismatch());
        }
        Ok(())
    }
}

enum Notification {
    LoginCompleted { id: Option<LoginId>, success: bool },
    AccountUpdated,
    ConfigWarning,
    RemoteControlStatus,
}

/// A version-pinned Codex app-server authentication session.
///
/// The caller must explicitly trust the executable and prepare a Codex
/// [`ProviderHome`] capability. This adapter never reads Codex credentials. The
/// provider home isolates filesystem configuration, but does not imply OS-keyring
/// isolation.
pub struct CodexAuth {
    sidecar: JsonlSidecar,
    home: ProviderHome,
    timeouts: CodexAuthTimeouts,
    next_request_id: i64,
    cached_state: AuthState,
    lifecycle: LoginLifecycle,
    terminal: Option<TerminalRecord>,
    poisoned: bool,
}

impl fmt::Debug for CodexAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAuth")
            .field("service", &SubscriptionService::OpenAiCodex)
            .field("cached_state", &self.cached_state)
            .field("pending", &!matches!(self.lifecycle, LoginLifecycle::Idle))
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl CodexAuth {
    pub async fn connect(
        executable: &TrustedExecutable,
        home: ProviderHome,
        sidecar_limits: SidecarLimits,
        timeouts: CodexAuthTimeouts,
    ) -> Result<Self, AuthError> {
        let timeouts = timeouts.validate()?;
        home.write_static_file("config.toml", KEYRING_CONFIG)
            .map_err(map_sidecar_error)?;

        let specification = SidecarCommand {
            executable: executable.canonical_path().to_path_buf(),
            arguments: vec![
                OsString::from("app-server"),
                OsString::from("--strict-config"),
                OsString::from("-c"),
                OsString::from("cli_auth_credentials_store=\"keyring\""),
                OsString::from("--listen"),
                OsString::from("stdio://"),
            ],
            version_arguments: vec![OsString::from("--version")],
            version_output: VersionOutputFormat::ExactPrefixedVersion {
                prefix: "codex-cli",
                version: "0.136.0",
            },
            // `spawn_in_home` uses the held capability instead of reopening this path.
            isolated_home: PathBuf::new(),
            supported_versions: VersionReq::parse(CODEX_VERSION)
                .expect("the pinned Codex version requirement is valid"),
        };
        let sidecar = JsonlSidecar::spawn_in_home(
            specification,
            executable,
            &home,
            NotificationPolicy::QueueBounded,
            sidecar_limits,
        )
        .await
        .map_err(map_sidecar_error)?;

        let mut auth = Self {
            sidecar,
            home,
            timeouts,
            next_request_id: 0,
            cached_state: AuthState::SignedOut,
            lifecycle: LoginLifecycle::Idle,
            terminal: None,
            poisoned: false,
        };
        auth.initialize().await?;
        auth.cached_state = auth.read_account_until(None).await?;
        Ok(auth)
    }

    #[must_use]
    pub const fn cached_state(&self) -> AuthState {
        self.cached_state
    }

    async fn initialize(&mut self) -> Result<(), AuthError> {
        let result = self
            .request_result(
                "initialize",
                Some(json!({
                    "clientInfo": {
                        "name": "carl",
                        "title": "Carl",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                })),
                None,
            )
            .await?;
        let mut result = into_object(result)?;
        if !has_exact_keys(
            &result,
            &["userAgent", "codexHome", "platformFamily", "platformOs"],
        ) {
            return Err(protocol_mismatch());
        }
        take_string(&mut result, "userAgent")?;
        let codex_home = take_string(&mut result, "codexHome")?;
        take_string(&mut result, "platformFamily")?;
        take_string(&mut result, "platformOs")?;
        if !self.home.matches_path(PathBuf::from(codex_home)) {
            return Err(protocol_mismatch());
        }
        self.sidecar
            .notify(json!({"method": "initialized"}))
            .map_err(map_sidecar_error)?;

        let mut operation = NotificationOperation::for_duration(self.timeouts.request)?;
        loop {
            let wait = operation.remaining()?;
            let notification = tokio::time::timeout(wait, self.sidecar.next_notification())
                .await
                .map_err(|_| timed_out())?
                .map_err(map_sidecar_error)?;
            operation.consume_notification()?;
            match parse_notification(notification)? {
                Notification::ConfigWarning => {}
                Notification::RemoteControlStatus => return Ok(()),
                Notification::AccountUpdated | Notification::LoginCompleted { .. } => {
                    return Err(protocol_mismatch());
                }
            }
        }
    }

    async fn request_result(
        &mut self,
        method: &'static str,
        params: Option<Value>,
        overall_deadline: Option<Instant>,
    ) -> Result<Value, AuthError> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(protocol_mismatch)?;
        let mut request = Map::new();
        request.insert("id".to_owned(), Value::from(id));
        request.insert("method".to_owned(), Value::String(method.to_owned()));
        if let Some(params) = params {
            request.insert("params".to_owned(), params);
        }

        let wait = bounded_wait(self.timeouts.request, overall_deadline)?;
        let response = tokio::time::timeout(wait, self.sidecar.request(Value::Object(request)))
            .await
            .map_err(|_| timed_out())?
            .map_err(map_sidecar_error)?;
        parse_response(response, id)
    }

    async fn read_account_until(
        &mut self,
        overall_deadline: Option<Instant>,
    ) -> Result<AuthState, AuthError> {
        let result = self
            .request_result(
                "account/read",
                Some(json!({"refreshToken": false})),
                overall_deadline,
            )
            .await?;
        parse_account(result)
    }

    async fn start_login_inner(&mut self, method: AuthMethod) -> Result<LoginChallenge, AuthError> {
        self.ensure_usable()?;
        if !matches!(self.lifecycle, LoginLifecycle::Idle) {
            return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
        }
        let login_type = match method {
            AuthMethod::BrowserOAuth => "chatgpt",
            AuthMethod::DeviceCode => "chatgptDeviceCode",
            AuthMethod::ProviderManaged => {
                return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
            }
        };
        let result = match self
            .request_result(
                "account/login/start",
                Some(json!({"type": login_type})),
                None,
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                self.stop_and_poison().await;
                return Err(error);
            }
        };
        let recoverable_id = recover_login_id(&result);
        let (id, challenge) = match parse_login_challenge(result, method) {
            Ok(challenge) => challenge,
            Err(error) => {
                let canceled = if let Some(id) = recoverable_id {
                    self.cancel_failed_start(id).await.is_ok()
                } else {
                    false
                };
                if !canceled {
                    self.stop_and_poison().await;
                }
                return Err(error);
            }
        };
        let deadline = Instant::now()
            .checked_add(self.timeouts.login)
            .ok_or_else(protocol_mismatch)?;
        self.lifecycle = LoginLifecycle::AwaitingCompletion(PendingLogin { id, deadline });
        self.terminal = None;
        self.cached_state = AuthState::Pending;
        Ok(challenge)
    }

    async fn query_state(&mut self) -> Result<AuthState, AuthError> {
        self.ensure_usable()?;
        match self.lifecycle {
            LoginLifecycle::Idle => {
                let mut operation = NotificationOperation::for_duration(self.timeouts.request)?;
                self.drain_idle_notifications(&mut operation).await?;
                let state = self.read_account_until(Some(operation.deadline)).await?;
                self.cached_state = state;
                Ok(state)
            }
            LoginLifecycle::CompletedAwaitingReload(id) => {
                let mut operation =
                    NotificationOperation::for_duration(self.timeouts.confirmation)?;
                self.confirm_login(id, &mut operation).await
            }
            LoginLifecycle::AwaitingCompletion(pending) => {
                self.await_login_completion(pending).await
            }
        }
    }

    async fn await_login_completion(
        &mut self,
        pending: PendingLogin,
    ) -> Result<AuthState, AuthError> {
        let mut operation = NotificationOperation::with_deadline(pending.deadline);
        loop {
            operation.check_deadline()?;
            let notification = if let Some(notification) = self
                .sidecar
                .try_next_notification()
                .await
                .map_err(map_sidecar_error)?
            {
                parse_notification(notification)?
            } else {
                let wait = operation.remaining()?;
                let notification = tokio::time::timeout(wait, self.sidecar.next_notification())
                    .await
                    .map_err(|_| timed_out())?
                    .map_err(map_sidecar_error)?;
                parse_notification(notification)?
            };
            operation.consume_notification()?;
            match notification {
                Notification::AccountUpdated
                | Notification::ConfigWarning
                | Notification::RemoteControlStatus => {}
                Notification::LoginCompleted { id: None, .. } => {}
                Notification::LoginCompleted {
                    id: Some(id),
                    success: _,
                } if id != pending.id => {}
                Notification::LoginCompleted {
                    id: Some(id),
                    success,
                } => {
                    let record = TerminalRecord { id, success };
                    self.record_terminal(record)?;
                    if !record.success {
                        self.lifecycle = LoginLifecycle::Idle;
                        self.cached_state = AuthState::SignedOut;
                        return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
                    }
                    self.lifecycle = LoginLifecycle::CompletedAwaitingReload(id);
                    operation.reset_deadline(self.timeouts.confirmation)?;
                    return self.confirm_login(id, &mut operation).await;
                }
            }
        }
    }

    async fn confirm_login(
        &mut self,
        login_id: LoginId,
        operation: &mut NotificationOperation,
    ) -> Result<AuthState, AuthError> {
        for _ in 0..MAX_CONFIRMATION_READS {
            operation.check_deadline()?;
            let state = self.read_account_until(Some(operation.deadline)).await?;
            if matches!(state, AuthState::SignedIn { .. }) {
                self.drain_confirmation_notifications(login_id, operation)
                    .await?;
                self.lifecycle = LoginLifecycle::Idle;
                self.cached_state = state;
                return Ok(state);
            }

            let wait = bounded_wait(self.timeouts.retry_interval, Some(operation.deadline))?;
            match tokio::time::timeout(wait, self.sidecar.next_notification()).await {
                Ok(Ok(notification)) => {
                    operation.consume_notification()?;
                    match parse_notification(notification)? {
                        Notification::AccountUpdated
                        | Notification::ConfigWarning
                        | Notification::RemoteControlStatus => {}
                        Notification::LoginCompleted { id: None, .. } => {}
                        Notification::LoginCompleted {
                            id: Some(id),
                            success: _,
                        } if id != login_id => {}
                        Notification::LoginCompleted {
                            id: Some(id),
                            success,
                        } => self.record_terminal(TerminalRecord { id, success })?,
                    }
                }
                Ok(Err(error)) => return Err(map_sidecar_error(error)),
                Err(_) => {}
            }
        }
        Err(timed_out())
    }

    async fn drain_confirmation_notifications(
        &mut self,
        login_id: LoginId,
        operation: &mut NotificationOperation,
    ) -> Result<(), AuthError> {
        loop {
            operation.check_deadline()?;
            let Some(notification) = self
                .sidecar
                .try_next_notification()
                .await
                .map_err(map_sidecar_error)?
            else {
                return Ok(());
            };
            operation.consume_notification()?;
            match parse_notification(notification)? {
                Notification::AccountUpdated
                | Notification::ConfigWarning
                | Notification::RemoteControlStatus => {}
                Notification::LoginCompleted { id: None, .. } => {}
                Notification::LoginCompleted {
                    id: Some(id),
                    success: _,
                } if id != login_id => {}
                Notification::LoginCompleted {
                    id: Some(id),
                    success,
                } => self.record_terminal(TerminalRecord { id, success })?,
            }
        }
    }

    async fn drain_idle_notifications(
        &mut self,
        operation: &mut NotificationOperation,
    ) -> Result<(), AuthError> {
        loop {
            operation.check_deadline()?;
            let Some(notification) = self
                .sidecar
                .try_next_notification()
                .await
                .map_err(map_sidecar_error)?
            else {
                return Ok(());
            };
            operation.consume_notification()?;
            match parse_notification(notification)? {
                Notification::AccountUpdated
                | Notification::ConfigWarning
                | Notification::RemoteControlStatus => {}
                Notification::LoginCompleted { id: None, .. } => {}
                Notification::LoginCompleted {
                    id: Some(id),
                    success,
                } => {
                    let record = TerminalRecord { id, success };
                    if let Some(terminal) = self.terminal
                        && terminal.id == id
                    {
                        self.record_terminal(record)?;
                    }
                }
            }
        }
    }

    fn record_terminal(&mut self, record: TerminalRecord) -> Result<(), AuthError> {
        if let Some(previous) = self.terminal
            && previous.id == record.id
        {
            if previous.success == record.success {
                return Ok(());
            }
            return Err(protocol_mismatch());
        }
        self.terminal = Some(record);
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), AuthError> {
        if self.poisoned {
            return Err(AuthError::from_code(AuthErrorCode::SidecarExited));
        }
        Ok(())
    }

    async fn stop_and_poison(&mut self) {
        self.poisoned = true;
        self.lifecycle = LoginLifecycle::Idle;
        self.terminal = None;
        let _ = self.sidecar.cancel().await;
    }

    async fn cancel_failed_start(&mut self, login_id: LoginId) -> Result<(), AuthError> {
        let result = self
            .request_result(
                "account/login/cancel",
                Some(json!({"loginId": login_id.into_wire()})),
                None,
            )
            .await?;
        if parse_cancel_status(result)? != "canceled" {
            return Err(protocol_mismatch());
        }
        Ok(())
    }

    async fn cancel_login_inner(&mut self) -> Result<(), AuthError> {
        self.ensure_usable()?;
        let Some(login_id) = self.lifecycle.login_id() else {
            return Ok(());
        };
        let result = self
            .request_result(
                "account/login/cancel",
                Some(json!({"loginId": login_id.into_wire()})),
                None,
            )
            .await?;
        match parse_cancel_status(result)?.as_str() {
            "canceled" => {
                let mut operation =
                    NotificationOperation::for_duration(self.timeouts.confirmation)?;
                self.reconcile_canceled(login_id, &mut operation).await?;
                self.record_terminal(TerminalRecord {
                    id: login_id,
                    success: false,
                })?;
                self.lifecycle = LoginLifecycle::Idle;
                self.cached_state = self.read_account_until(Some(operation.deadline)).await?;
                Ok(())
            }
            "notFound" => self.reconcile_not_found(login_id).await,
            _ => Err(protocol_mismatch()),
        }
    }

    async fn reconcile_canceled(
        &mut self,
        login_id: LoginId,
        operation: &mut NotificationOperation,
    ) -> Result<(), AuthError> {
        loop {
            operation.check_deadline()?;
            let Some(notification) = self
                .sidecar
                .try_next_notification()
                .await
                .map_err(map_sidecar_error)?
            else {
                return Ok(());
            };
            operation.consume_notification()?;
            match parse_notification(notification)? {
                Notification::AccountUpdated
                | Notification::ConfigWarning
                | Notification::RemoteControlStatus => {}
                Notification::LoginCompleted {
                    id: Some(id),
                    success,
                } if id == login_id => {
                    let record = TerminalRecord { id, success };
                    self.record_terminal(record)?;
                    if record.success {
                        return Err(protocol_mismatch());
                    }
                }
                Notification::LoginCompleted { .. } => {}
            }
        }
    }

    async fn reconcile_not_found(&mut self, login_id: LoginId) -> Result<(), AuthError> {
        let mut operation = NotificationOperation::for_duration(self.timeouts.confirmation)?;
        self.drain_confirmation_notifications(login_id, &mut operation)
            .await?;
        if self
            .terminal
            .is_some_and(|record| record.id == login_id && record.success)
        {
            self.lifecycle = LoginLifecycle::CompletedAwaitingReload(login_id);
            self.confirm_login(login_id, &mut operation).await?;
            return Ok(());
        }

        let state = self.read_account_until(Some(operation.deadline)).await?;
        self.lifecycle = LoginLifecycle::Idle;
        self.cached_state = state;
        Ok(())
    }

    async fn logout_inner(&mut self) -> Result<(), AuthError> {
        self.ensure_usable()?;
        let cancel_error = if self.lifecycle.login_id().is_some() {
            self.cancel_login_inner().await.err()
        } else {
            None
        };
        let logout_result = self
            .request_result("account/logout", None, None)
            .await
            .and_then(|result| {
                if into_object(result)?.is_empty() {
                    Ok(())
                } else {
                    Err(protocol_mismatch())
                }
            });
        if logout_result.is_ok() {
            self.lifecycle = LoginLifecycle::Idle;
            self.terminal = None;
            self.cached_state = AuthState::SignedOut;
        }
        logout_result?;
        if let Some(error) = cancel_error {
            return Err(error);
        }
        Ok(())
    }
}

impl SubscriptionAuthBroker for CodexAuth {
    fn service(&self) -> SubscriptionService {
        SubscriptionService::OpenAiCodex
    }

    fn auth_state(&mut self) -> AuthFuture<'_, AuthState> {
        Box::pin(async move { self.query_state().await })
    }

    fn start_login(&mut self, method: AuthMethod) -> AuthFuture<'_, LoginChallenge> {
        Box::pin(async move { self.start_login_inner(method).await })
    }

    fn logout(&mut self) -> AuthFuture<'_, ()> {
        Box::pin(async move { self.logout_inner().await })
    }

    fn cancel_login(&mut self) -> AuthFuture<'_, ()> {
        Box::pin(async move { self.cancel_login_inner().await })
    }
}

fn parse_response(response: Value, expected_id: i64) -> Result<Value, AuthError> {
    let mut response = into_object(response)?;
    if response.remove("id") != Some(Value::from(expected_id)) || response.len() != 1 {
        return Err(protocol_mismatch());
    }
    if let Some(result) = response.remove("result") {
        return Ok(result);
    }
    let Some(error) = response.remove("error") else {
        return Err(protocol_mismatch());
    };
    let code = validate_provider_error(&error)?;
    if matches!(code, -32602..=-32600) {
        Err(protocol_mismatch())
    } else {
        Err(AuthError::from_code(AuthErrorCode::ProviderRejected))
    }
}

fn validate_provider_error(error: &Value) -> Result<i64, AuthError> {
    let object = error.as_object().ok_or_else(protocol_mismatch)?;
    if object.len() < 2
        || object.len() > 3
        || !object
            .get("code")
            .is_some_and(|value| value.as_i64().is_some())
        || !object.get("message").is_some_and(Value::is_string)
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "code" | "message" | "data"))
    {
        return Err(protocol_mismatch());
    }
    object
        .get("code")
        .and_then(Value::as_i64)
        .ok_or_else(protocol_mismatch)
}

fn parse_account(result: Value) -> Result<AuthState, AuthError> {
    let mut result = into_object(result)?;
    if !has_exact_keys(&result, &["account", "requiresOpenaiAuth"])
        || result.remove("requiresOpenaiAuth") != Some(Value::Bool(true))
    {
        return Err(protocol_mismatch());
    }
    let account = result.remove("account").ok_or_else(protocol_mismatch)?;
    if account.is_null() {
        return Ok(AuthState::SignedOut);
    }
    let mut account = into_object(account)?;
    let account_type = take_string(&mut account, "type")?;
    match account_type.as_str() {
        "chatgpt" => {
            if !has_exact_keys_remaining(&account, &["email", "planType"]) {
                return Err(protocol_mismatch());
            }
            if !account.get("email").is_some_and(Value::is_string) {
                return Err(protocol_mismatch());
            }
            let plan = account
                .get("planType")
                .and_then(Value::as_str)
                .and_then(parse_plan)
                .ok_or_else(protocol_mismatch)?;
            Ok(AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: Some(plan),
            })
        }
        "apiKey" | "amazonBedrock" if account.is_empty() => Ok(AuthState::SignedOut),
        _ => Err(protocol_mismatch()),
    }
}

fn parse_login_challenge(
    result: Value,
    requested_method: AuthMethod,
) -> Result<(LoginId, LoginChallenge), AuthError> {
    let mut result = into_object(result)?;
    let response_type = take_string(&mut result, "type")?;
    let login_id = take_string(&mut result, "loginId")?;
    let login_id = LoginId::parse(&login_id)?;
    match (requested_method, response_type.as_str()) {
        (AuthMethod::BrowserOAuth, "chatgpt") => {
            if !has_exact_keys_remaining(&result, &["authUrl"]) {
                return Err(protocol_mismatch());
            }
            let auth_url = take_string(&mut result, "authUrl")?;
            validate_browser_url(&auth_url)?;
            Ok((
                login_id,
                LoginChallenge::Browser {
                    authorization_url: AuthorizationUrl::parse(&auth_url)?,
                },
            ))
        }
        (AuthMethod::DeviceCode, "chatgptDeviceCode") => {
            if !has_exact_keys_remaining(&result, &["verificationUrl", "userCode"]) {
                return Err(protocol_mismatch());
            }
            let verification_url = take_string(&mut result, "verificationUrl")?;
            validate_device_url(&verification_url)?;
            let user_code = take_string(&mut result, "userCode")?;
            Ok((
                login_id,
                LoginChallenge::Device {
                    verification_url: AuthorizationUrl::parse(&verification_url)?,
                    user_code: UserCode::parse(&user_code)?,
                },
            ))
        }
        _ => Err(protocol_mismatch()),
    }
}

fn recover_login_id(result: &Value) -> Option<LoginId> {
    result
        .as_object()
        .and_then(|result| result.get("loginId"))
        .and_then(Value::as_str)
        .and_then(|login_id| LoginId::parse(login_id).ok())
}

fn parse_cancel_status(result: Value) -> Result<String, AuthError> {
    let mut result = into_object(result)?;
    if !has_exact_keys(&result, &["status"]) {
        return Err(protocol_mismatch());
    }
    take_string(&mut result, "status")
}

fn parse_notification(notification: Value) -> Result<Notification, AuthError> {
    let mut notification = into_object(notification)?;
    if !has_exact_keys(&notification, &["method", "params"]) {
        return Err(protocol_mismatch());
    }
    let method = take_string(&mut notification, "method")?;
    let params = notification
        .remove("params")
        .ok_or_else(protocol_mismatch)?;
    let mut params = into_object(params)?;
    match method.as_str() {
        "account/login/completed" => {
            if !params.contains_key("success")
                || params
                    .keys()
                    .any(|key| !matches!(key.as_str(), "loginId" | "success" | "error"))
            {
                return Err(protocol_mismatch());
            }
            let success = params
                .remove("success")
                .and_then(|value| value.as_bool())
                .ok_or_else(protocol_mismatch)?;
            let id = match params.remove("loginId") {
                None | Some(Value::Null) => None,
                Some(Value::String(login_id)) => Some(LoginId::parse(&login_id)?),
                Some(_) => return Err(protocol_mismatch()),
            };
            match (success, params.remove("error")) {
                (true, None | Some(Value::Null)) | (false, Some(Value::String(_))) => {}
                _ => return Err(protocol_mismatch()),
            }
            Ok(Notification::LoginCompleted { id, success })
        }
        "account/updated" => {
            if params
                .keys()
                .any(|key| !matches!(key.as_str(), "authMode" | "planType"))
            {
                return Err(protocol_mismatch());
            }
            if let Some(auth_mode) = params.remove("authMode")
                && !auth_mode.is_null()
                && !auth_mode.as_str().is_some_and(|value| {
                    matches!(
                        value,
                        "apikey" | "chatgpt" | "chatgptAuthTokens" | "agentIdentity"
                    )
                })
            {
                return Err(protocol_mismatch());
            }
            if let Some(plan_type) = params.remove("planType")
                && !plan_type.is_null()
                && !plan_type.as_str().and_then(parse_plan).is_some()
            {
                return Err(protocol_mismatch());
            }
            Ok(Notification::AccountUpdated)
        }
        "configWarning" => {
            validate_config_warning(&params)?;
            Ok(Notification::ConfigWarning)
        }
        "remoteControl/status/changed" => {
            validate_remote_control_status(&params)?;
            Ok(Notification::RemoteControlStatus)
        }
        _ => Err(protocol_mismatch()),
    }
}

fn validate_browser_url(value: &str) -> Result<(), AuthError> {
    let url = parse_pinned_url(value, "/oauth/authorize")?;
    let mut pairs = url.query_pairs();
    require_query_value(&mut pairs, "response_type", "code")?;
    require_query_value(&mut pairs, "client_id", CODEX_OAUTH_CLIENT_ID)?;
    let redirect = next_query_value(&mut pairs, "redirect_uri")?;
    validate_redirect_uri(&redirect)?;
    require_query_value(&mut pairs, "scope", CODEX_OAUTH_SCOPE)?;
    let code_challenge = next_query_value(&mut pairs, "code_challenge")?;
    if !is_pkce_value(&code_challenge) {
        return Err(invalid_authorization_url());
    }
    require_query_value(&mut pairs, "code_challenge_method", "S256")?;
    require_query_value(&mut pairs, "id_token_add_organizations", "true")?;
    require_query_value(&mut pairs, "codex_cli_simplified_flow", "true")?;
    let state = next_query_value(&mut pairs, "state")?;
    if !is_pkce_value(&state) {
        return Err(invalid_authorization_url());
    }
    require_query_value(&mut pairs, "originator", "carl")?;
    if pairs.next().is_some() {
        return Err(invalid_authorization_url());
    }
    Ok(())
}

fn next_query_value<'a>(
    pairs: &mut url::form_urlencoded::Parse<'a>,
    expected_key: &str,
) -> Result<Cow<'a, str>, AuthError> {
    let (key, value) = pairs.next().ok_or_else(invalid_authorization_url)?;
    if key != expected_key {
        return Err(invalid_authorization_url());
    }
    Ok(value)
}

fn require_query_value(
    pairs: &mut url::form_urlencoded::Parse<'_>,
    expected_key: &str,
    expected_value: &str,
) -> Result<(), AuthError> {
    if next_query_value(pairs, expected_key)? != expected_value {
        return Err(invalid_authorization_url());
    }
    Ok(())
}

fn validate_redirect_uri(value: &str) -> Result<(), AuthError> {
    let redirect = Url::parse(value).map_err(|_| invalid_authorization_url())?;
    if redirect.scheme() != "http"
        || redirect.host_str() != Some("localhost")
        || !matches!(redirect.port(), Some(1455 | 1457))
        || redirect.path() != "/auth/callback"
        || redirect.query().is_some()
        || redirect.fragment().is_some()
        || !redirect.username().is_empty()
        || redirect.password().is_some()
    {
        return Err(invalid_authorization_url());
    }
    Ok(())
}

fn is_pkce_value(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_device_url(value: &str) -> Result<(), AuthError> {
    let url = parse_pinned_url(value, "/codex/device")?;
    if url.query().is_some() {
        return Err(invalid_authorization_url());
    }
    Ok(())
}

fn parse_pinned_url(value: &str, expected_path: &str) -> Result<Url, AuthError> {
    let url = Url::parse(value).map_err(|_| invalid_authorization_url())?;
    if url.scheme() != "https"
        || url.host_str() != Some("auth.openai.com")
        || url.port().is_some()
        || url.path() != expected_path
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid_authorization_url());
    }
    Ok(url)
}

fn parse_plan(value: &str) -> Option<SubscriptionPlan> {
    match value {
        "free" => Some(SubscriptionPlan::Free),
        "go" => Some(SubscriptionPlan::Go),
        "plus" => Some(SubscriptionPlan::Plus),
        "pro" => Some(SubscriptionPlan::Pro),
        "prolite" => Some(SubscriptionPlan::ProLite),
        "team" | "self_serve_business_usage_based" => Some(SubscriptionPlan::Team),
        "business" | "enterprise_cbp_usage_based" => Some(SubscriptionPlan::Business),
        "enterprise" => Some(SubscriptionPlan::Enterprise),
        "edu" => Some(SubscriptionPlan::Education),
        "unknown" => Some(SubscriptionPlan::Unknown),
        _ => None,
    }
}

fn validate_config_warning(params: &Map<String, Value>) -> Result<(), AuthError> {
    if !params.get("summary").is_some_and(Value::is_string)
        || params
            .keys()
            .any(|key| !matches!(key.as_str(), "summary" | "details" | "path" | "range"))
    {
        return Err(protocol_mismatch());
    }
    for key in ["details", "path"] {
        if let Some(value) = params.get(key)
            && !value.is_null()
            && !value.is_string()
        {
            return Err(protocol_mismatch());
        }
    }
    if let Some(range) = params.get("range")
        && !range.is_null()
    {
        let range = range.as_object().ok_or_else(protocol_mismatch)?;
        if !has_exact_keys(range, &["start", "end"])
            || !["start", "end"].iter().all(|key| {
                range.get(*key).is_some_and(|position| {
                    position.as_object().is_some_and(|position| {
                        has_exact_keys(position, &["line", "column"])
                            && position
                                .get("line")
                                .is_some_and(|value| value.as_u64().is_some())
                            && position
                                .get("column")
                                .is_some_and(|value| value.as_u64().is_some())
                    })
                })
            })
        {
            return Err(protocol_mismatch());
        }
    }
    Ok(())
}

fn validate_remote_control_status(params: &Map<String, Value>) -> Result<(), AuthError> {
    if !params.get("installationId").is_some_and(Value::is_string)
        || !params.get("serverName").is_some_and(Value::is_string)
        || !params
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| {
                matches!(status, "disabled" | "connecting" | "connected" | "errored")
            })
        || params.keys().any(|key| {
            !matches!(
                key.as_str(),
                "installationId" | "serverName" | "status" | "environmentId"
            )
        })
    {
        return Err(protocol_mismatch());
    }
    if let Some(environment_id) = params.get("environmentId")
        && !environment_id.is_null()
        && !environment_id.is_string()
    {
        return Err(protocol_mismatch());
    }
    Ok(())
}

fn into_object(value: Value) -> Result<Map<String, Value>, AuthError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(protocol_mismatch()),
    }
}

fn take_string(object: &mut Map<String, Value>, key: &str) -> Result<String, AuthError> {
    match object.remove(key) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(protocol_mismatch()),
    }
}

fn has_exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn has_exact_keys_remaining(object: &Map<String, Value>, keys: &[&str]) -> bool {
    has_exact_keys(object, keys)
}

fn bounded_wait(
    maximum: Duration,
    overall_deadline: Option<Instant>,
) -> Result<Duration, AuthError> {
    overall_deadline.map_or(Ok(maximum), |deadline| {
        remaining(deadline).map(|left| left.min(maximum))
    })
}

fn remaining(deadline: Instant) -> Result<Duration, AuthError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(timed_out)
}

fn map_sidecar_error(error: SidecarError) -> AuthError {
    let code = match error.code() {
        SidecarErrorCode::ExecutableMissing => AuthErrorCode::ExecutableMissing,
        SidecarErrorCode::UnsupportedVersion => AuthErrorCode::UnsupportedVersion,
        SidecarErrorCode::ForegroundRequired => AuthErrorCode::ForegroundRequired,
        SidecarErrorCode::UnsafeProviderFile => AuthErrorCode::UnsafeCredentialStore,
        SidecarErrorCode::ProtocolViolation | SidecarErrorCode::DuplicateRequestId => {
            AuthErrorCode::ProtocolMismatch
        }
        SidecarErrorCode::SidecarExited => AuthErrorCode::SidecarExited,
        SidecarErrorCode::Cancelled => AuthErrorCode::Cancelled,
        SidecarErrorCode::TimedOut => AuthErrorCode::TimedOut,
        SidecarErrorCode::ExecutableUnavailable
        | SidecarErrorCode::UnsafeExecutable
        | SidecarErrorCode::InvalidProviderHome
        | SidecarErrorCode::InvalidConfiguration
        | SidecarErrorCode::SpawnFailed => AuthErrorCode::ProviderRejected,
    };
    AuthError::from_code(code)
}

fn protocol_mismatch() -> AuthError {
    AuthError::from_code(AuthErrorCode::ProtocolMismatch)
}

fn invalid_authorization_url() -> AuthError {
    AuthError::from_code(AuthErrorCode::InvalidAuthorizationUrl)
}

fn timed_out() -> AuthError {
    AuthError::from_code(AuthErrorCode::TimedOut)
}
