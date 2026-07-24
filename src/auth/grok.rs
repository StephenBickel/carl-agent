use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use semver::VersionReq;
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::{
    AuthError, AuthErrorCode, AuthFuture, AuthMethod, AuthState, LoginChallenge,
    SubscriptionAuthBroker, SubscriptionService,
};
use crate::sidecar::{
    ForegroundProcess, JsonlSidecar, LocalForegroundAuthorization, NotificationPolicy,
    ProviderFileMetadata, ProviderFilePreflight, ProviderHome, SidecarCommand, SidecarError,
    SidecarErrorCode, SidecarLimits, TrustedExecutable, VersionOutputFormat,
};

const GROK_VERSION: &str = "0.2.111";
const GROK_VERSION_REQUIREMENT: &str = "=0.2.111";
const REQUIREMENTS_POLICY: &[u8] =
    b"[cli]\nauto_update = false\n\n[grok_com_config]\ndisable_api_key_auth = true\n";
const REQUIREMENTS_FILENAME: &str = "requirements.toml";
const CREDENTIAL_FILENAME: &str = "auth.json";
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FOREGROUND_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_META_BYTES: usize = 4 * 1024;
const MAX_META_DEPTH: usize = 4;
const MAX_META_NODES: usize = 64;
const MAX_META_CONTAINER_ITEMS: usize = 32;
const MAX_META_STRING_BYTES: usize = 1024;
const MAX_AUTH_METHODS: usize = 32;
const MAX_AUTH_METHOD_TEXT_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrokAuthTimeouts {
    request: Duration,
    foreground: Duration,
}

impl GrokAuthTimeouts {
    #[must_use]
    pub const fn new(request: Duration, foreground: Duration) -> Self {
        Self {
            request,
            foreground,
        }
    }

    fn validate(self) -> Result<Self, AuthError> {
        if self.request.is_zero()
            || self.request > MAX_REQUEST_TIMEOUT
            || self.foreground.is_zero()
            || self.foreground > MAX_FOREGROUND_TIMEOUT
        {
            return Err(protocol_mismatch());
        }
        Ok(self)
    }
}

impl Default for GrokAuthTimeouts {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(5),
            foreground: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForegroundAction {
    Login,
    Logout,
}

enum RpcResponse {
    Success(Value),
    Error(i64),
}

enum InitializeOutcome {
    SignedOut,
    Authenticate,
}

/// Version-pinned Grok Build authentication against an isolated provider home.
///
/// [`Self::connect`] deliberately creates a status-only broker. Only Carl's local
/// CLI path can construct a broker carrying the opaque foreground authorization
/// capability required for provider-owned login and logout ceremonies.
///
/// The isolated home and metadata rechecks protect Carl from accidental credential
/// exposure and ordinary filesystem substitution, not from a hostile process running
/// as the same operating-system user. Grok may also apply root-owned `/etc/grok`
/// policy outside this home. The exact version check is a compatibility gate; the
/// caller must establish executable publisher trust before constructing
/// [`TrustedExecutable`].
///
/// Provider-home operation serialization is process-local. Every public CLI or daemon
/// entry point must also retain a [`crate::sidecar::DataRootLock`] for its Carl data
/// root through provider shutdown and reconciliation.
pub struct GrokAuth {
    executable: TrustedExecutable,
    home: ProviderHome,
    sidecar_limits: SidecarLimits,
    timeouts: GrokAuthTimeouts,
    cached_state: AuthState,
    local_foreground: Option<LocalForegroundAuthorization>,
    foreground: Option<ForegroundProcess>,
    foreground_action: Option<ForegroundAction>,
    operation_lock: Arc<AsyncMutex<()>>,
    operation_guard: Option<OwnedMutexGuard<()>>,
}

impl fmt::Debug for GrokAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrokAuth")
            .field("service", &SubscriptionService::XaiGrok)
            .field("cached_state", &self.cached_state)
            .field("local_foreground", &self.local_foreground.is_some())
            .field("operation_pending", &self.foreground_action.is_some())
            .finish_non_exhaustive()
    }
}

impl GrokAuth {
    /// Connect a status-only broker suitable for nonlocal adapters.
    pub async fn connect(
        executable: &TrustedExecutable,
        home: ProviderHome,
        sidecar_limits: SidecarLimits,
        timeouts: GrokAuthTimeouts,
    ) -> Result<Self, AuthError> {
        Self::connect_inner(executable, home, sidecar_limits, timeouts, None).await
    }

    /// Connect a broker authorized by Carl's explicit local foreground CLI path.
    #[allow(dead_code)]
    pub(crate) async fn connect_local(
        executable: &TrustedExecutable,
        home: ProviderHome,
        sidecar_limits: SidecarLimits,
        timeouts: GrokAuthTimeouts,
        authorization: LocalForegroundAuthorization,
    ) -> Result<Self, AuthError> {
        Self::connect_inner(
            executable,
            home,
            sidecar_limits,
            timeouts,
            Some(authorization),
        )
        .await
    }

    async fn connect_inner(
        executable: &TrustedExecutable,
        home: ProviderHome,
        sidecar_limits: SidecarLimits,
        timeouts: GrokAuthTimeouts,
        local_foreground: Option<LocalForegroundAuthorization>,
    ) -> Result<Self, AuthError> {
        home.require_profile(crate::sidecar::ProviderEnvironmentProfile::Grok)
            .map_err(map_sidecar_error)?;
        let timeouts = timeouts.validate()?;
        let operation_lock = home.operation_lock();
        let mut broker = Self {
            executable: executable.clone(),
            home,
            sidecar_limits,
            timeouts,
            cached_state: AuthState::SignedOut,
            local_foreground,
            foreground: None,
            foreground_action: None,
            operation_lock,
            operation_guard: None,
        };
        let guard = broker.lock_operation().await?;
        let compatibility = broker.verify_compatibility().await;
        let result = match compatibility {
            Ok(()) => broker.probe_auth_state().await,
            Err(error) => Err(error),
        };
        drop(guard);
        broker.cached_state = result?;
        Ok(broker)
    }

    #[must_use]
    pub const fn cached_state(&self) -> AuthState {
        self.cached_state
    }

    async fn lock_operation(&self) -> Result<OwnedMutexGuard<()>, AuthError> {
        let operation_lock = Arc::clone(&self.operation_lock);
        tokio::time::timeout(self.timeouts.request, operation_lock.lock_owned())
            .await
            .map_err(|_| timed_out())
    }

    fn finish_operation(&mut self) {
        self.foreground = None;
        self.foreground_action = None;
        self.operation_guard = None;
    }

    fn specification(&self, arguments: Vec<OsString>) -> SidecarCommand {
        SidecarCommand {
            executable: self.executable.canonical_path().to_path_buf(),
            arguments,
            version_arguments: vec![
                OsString::from("--no-auto-update"),
                OsString::from("version"),
            ],
            version_output: VersionOutputFormat::SingleExactSemverToken {
                version: GROK_VERSION,
            },
            isolated_home: PathBuf::new(),
            supported_versions: VersionReq::parse(GROK_VERSION_REQUIREMENT)
                .expect("the pinned Grok version requirement is valid"),
        }
    }

    fn inspect_credentials(&self) -> Result<ProviderFileMetadata, AuthError> {
        self.home
            .inspect_owner_only_file(CREDENTIAL_FILENAME, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(map_sidecar_error)
    }

    async fn verify_compatibility(&self) -> Result<(), AuthError> {
        self.home
            .write_static_file(REQUIREMENTS_FILENAME, REQUIREMENTS_POLICY)
            .map_err(map_sidecar_error)?;
        self.inspect_credentials()?;
        let version = self
            .specification(Vec::new())
            .detect_version_in_home(&self.executable, &self.home, self.sidecar_limits)
            .await
            .map(|_| ())
            .map_err(map_sidecar_error);
        let policy = self
            .home
            .write_static_file(REQUIREMENTS_FILENAME, REQUIREMENTS_POLICY)
            .map_err(map_sidecar_error);
        let credentials = self.inspect_credentials();
        policy?;
        credentials?;
        version
    }

    async fn probe_auth_state(&self) -> Result<AuthState, AuthError> {
        let specification = self.specification(vec![
            OsString::from("--no-auto-update"),
            OsString::from("agent"),
            OsString::from("stdio"),
        ]);
        let sidecar =
            JsonlSidecar::spawn_in_home_after_compatibility_check_with_provider_file_preflight(
                specification,
                &self.executable,
                &self.home,
                ProviderFilePreflight::new(
                    Path::new(REQUIREMENTS_FILENAME),
                    REQUIREMENTS_POLICY,
                    Path::new(CREDENTIAL_FILENAME),
                    MAX_CREDENTIAL_FILE_BYTES,
                ),
                NotificationPolicy::Reject,
                self.sidecar_limits,
            );
        let sidecar = match sidecar {
            Ok(sidecar) => sidecar,
            Err(error) => {
                self.inspect_credentials()?;
                return Err(map_sidecar_error(error));
            }
        };

        let result = self.probe_with_sidecar(&sidecar).await;
        let cleanup = sidecar.cancel().await.map_err(map_sidecar_error);
        let credentials = self.inspect_credentials()?;
        cleanup?;
        let state = result?;
        if matches!(state, AuthState::SignedIn { .. }) && credentials != ProviderFileMetadata::Safe
        {
            return Err(protocol_mismatch());
        }
        Ok(state)
    }

    async fn probe_with_sidecar(&self, sidecar: &JsonlSidecar) -> Result<AuthState, AuthError> {
        let initialize = self
            .request(
                sidecar,
                json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": 1,
                        "clientCapabilities": {
                            "fs": {
                                "readTextFile": false,
                                "writeTextFile": false,
                            },
                            "terminal": false,
                        },
                        "clientInfo": {
                            "name": "carl",
                            "title": "Carl",
                            "version": env!("CARGO_PKG_VERSION"),
                        },
                    },
                }),
            )
            .await?;
        let initialize = match parse_rpc_response(initialize, 0)? {
            RpcResponse::Success(result) => parse_initialize_result(result)?,
            RpcResponse::Error(-32000) => return Ok(AuthState::SignedOut),
            RpcResponse::Error(code) => return Err(map_provider_error(code)),
        };
        if matches!(initialize, InitializeOutcome::SignedOut) {
            return Ok(AuthState::SignedOut);
        }

        let authenticate = self
            .request(
                sidecar,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "authenticate",
                    "params": {
                        "methodId": "cached_token",
                        "_meta": {"headless": true},
                    },
                }),
            )
            .await?;
        match parse_rpc_response(authenticate, 1)? {
            RpcResponse::Success(result) => {
                validate_authenticate_result(result)?;
                Ok(AuthState::SignedIn {
                    method: AuthMethod::ProviderManaged,
                    plan: None,
                })
            }
            RpcResponse::Error(-32000) => Ok(AuthState::SignedOut),
            RpcResponse::Error(code) => Err(map_provider_error(code)),
        }
    }

    async fn request(&self, sidecar: &JsonlSidecar, request: Value) -> Result<Value, AuthError> {
        tokio::time::timeout(self.timeouts.request, sidecar.request(request))
            .await
            .map_err(|_| timed_out())?
            .map_err(map_sidecar_error)
    }

    fn prepare_foreground(&self, arguments: &[OsString]) -> Result<ForegroundProcess, AuthError> {
        let authorization = self
            .local_foreground
            .as_ref()
            .ok_or_else(|| AuthError::from_code(AuthErrorCode::ForegroundRequired))?;
        self.home
            .write_static_file(REQUIREMENTS_FILENAME, REQUIREMENTS_POLICY)
            .map_err(map_sidecar_error)?;
        self.inspect_credentials()?;
        let process = self
            .executable
            .spawn_foreground(authorization, arguments, &self.home, self.sidecar_limits)
            .map_err(map_sidecar_error);
        if process.is_err() {
            self.inspect_credentials()?;
        }
        process
    }

    async fn start_login_inner(&mut self, method: AuthMethod) -> Result<LoginChallenge, AuthError> {
        let arguments = match method {
            AuthMethod::BrowserOAuth => {
                vec![OsString::from("--no-auto-update"), OsString::from("login")]
            }
            AuthMethod::DeviceCode => vec![
                OsString::from("--no-auto-update"),
                OsString::from("login"),
                OsString::from("--device-auth"),
            ],
            AuthMethod::ProviderManaged => {
                return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
            }
        };
        if self.local_foreground.is_none() {
            return Err(AuthError::from_code(AuthErrorCode::ForegroundRequired));
        }
        if self.foreground_action.is_some() {
            return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
        }

        let guard = self.lock_operation().await?;
        let process = self.prepare_foreground(&arguments)?;
        self.foreground = Some(process);
        self.foreground_action = Some(ForegroundAction::Login);
        self.operation_guard = Some(guard);
        self.cached_state = AuthState::Pending;

        let wait = {
            let process = self
                .foreground
                .as_mut()
                .expect("the foreground login process is retained");
            tokio::time::timeout(self.timeouts.foreground, process.wait()).await
        };
        match wait {
            Ok(Ok(_)) => {
                self.foreground = None;
                let state = self.reconcile_after_foreground().await;
                self.finish_operation();
                let state = state?;
                if matches!(state, AuthState::SignedIn { .. }) {
                    Ok(LoginChallenge::ProviderManaged)
                } else {
                    Err(AuthError::from_code(AuthErrorCode::ProviderRejected))
                }
            }
            Ok(Err(error)) => {
                let primary = map_sidecar_error(error);
                self.reap_and_reconcile_with_primary(primary).await
            }
            Err(_) => self.reap_and_reconcile_with_primary(timed_out()).await,
        }
    }

    async fn reap_and_reconcile_with_primary<T>(
        &mut self,
        primary: AuthError,
    ) -> Result<T, AuthError> {
        let cleanup = self.reap_foreground().await;
        cleanup?;
        let reconciliation = self.reconcile_after_foreground().await;
        self.finish_operation();
        reconciliation?;
        Err(primary)
    }

    async fn reap_foreground(&mut self) -> Result<(), AuthError> {
        let result = match self.foreground.as_mut() {
            Some(process) => process.cancel().await.map_err(map_sidecar_error),
            None => Ok(()),
        };
        if result.is_ok() {
            self.foreground = None;
        }
        self.inspect_credentials()?;
        result
    }

    async fn reconcile_after_foreground(&mut self) -> Result<AuthState, AuthError> {
        self.inspect_credentials()?;
        let state = self.probe_auth_state().await?;
        self.cached_state = state;
        Ok(state)
    }

    async fn query_state(&mut self) -> Result<AuthState, AuthError> {
        if self.foreground_action.is_some() {
            return Ok(AuthState::Pending);
        }
        let guard = self.lock_operation().await?;
        let result = self.probe_auth_state().await;
        drop(guard);
        self.cached_state = result?;
        Ok(self.cached_state)
    }

    async fn cancel_login_inner(&mut self) -> Result<(), AuthError> {
        if self.local_foreground.is_none() {
            return Err(AuthError::from_code(AuthErrorCode::ForegroundRequired));
        }
        if self.foreground_action.is_none() {
            return Ok(());
        }
        let cleanup = self.reap_foreground().await;
        cleanup?;
        let reconciliation = self.reconcile_after_foreground().await;
        self.finish_operation();
        reconciliation.map(|_| ())
    }

    async fn logout_inner(&mut self) -> Result<(), AuthError> {
        if self.local_foreground.is_none() {
            return Err(AuthError::from_code(AuthErrorCode::ForegroundRequired));
        }
        if self.foreground_action.is_some() {
            self.cancel_login_inner().await?;
        }

        let guard = self.lock_operation().await?;
        let arguments = [OsString::from("--no-auto-update"), OsString::from("logout")];
        let process = self.prepare_foreground(&arguments)?;
        self.foreground = Some(process);
        self.foreground_action = Some(ForegroundAction::Logout);
        self.operation_guard = Some(guard);

        let wait = {
            let process = self
                .foreground
                .as_mut()
                .expect("the foreground logout process is retained");
            tokio::time::timeout(self.timeouts.foreground, process.wait()).await
        };
        match wait {
            Ok(Ok(_)) => {
                self.foreground = None;
                let state = self.reconcile_after_foreground().await;
                self.finish_operation();
                if matches!(state?, AuthState::SignedOut) {
                    Ok(())
                } else {
                    Err(AuthError::from_code(AuthErrorCode::ProviderRejected))
                }
            }
            Ok(Err(error)) => {
                let primary = map_sidecar_error(error);
                self.reap_and_reconcile_with_primary(primary).await
            }
            Err(_) => self.reap_and_reconcile_with_primary(timed_out()).await,
        }
    }
}

impl SubscriptionAuthBroker for GrokAuth {
    fn service(&self) -> SubscriptionService {
        SubscriptionService::XaiGrok
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

    fn shutdown(&mut self) -> AuthFuture<'_, ()> {
        Box::pin(async move {
            if self.foreground_action.is_some() {
                self.cancel_login_inner().await
            } else {
                Ok(())
            }
        })
    }
}

fn parse_rpc_response(response: Value, expected_id: i64) -> Result<RpcResponse, AuthError> {
    let mut response = into_object(response)?;
    if response.remove("jsonrpc") != Some(Value::String("2.0".to_owned()))
        || response.remove("id") != Some(Value::from(expected_id))
        || response.contains_key("method")
        || response.contains_key("params")
    {
        return Err(protocol_mismatch());
    }
    match (response.remove("result"), response.remove("error")) {
        (Some(result), None) if response.is_empty() => Ok(RpcResponse::Success(result)),
        (None, Some(error)) if response.is_empty() => {
            Ok(RpcResponse::Error(validate_provider_error(&error)?))
        }
        _ => Err(protocol_mismatch()),
    }
}

fn validate_provider_error(error: &Value) -> Result<i64, AuthError> {
    let object = error.as_object().ok_or_else(protocol_mismatch)?;
    if object.len() < 2
        || object.len() > 3
        || !object
            .get("code")
            .is_some_and(|value| value.as_i64().is_some())
        || !object
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.len() <= MAX_META_BYTES)
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

fn map_provider_error(code: i64) -> AuthError {
    if code == -32700 || (-32603..=-32600).contains(&code) {
        protocol_mismatch()
    } else {
        AuthError::from_code(AuthErrorCode::ProviderRejected)
    }
}

fn parse_initialize_result(result: Value) -> Result<InitializeOutcome, AuthError> {
    let mut result = into_object(result)?;
    if result.keys().any(|key| {
        !matches!(
            key.as_str(),
            "protocolVersion" | "agentCapabilities" | "agentInfo" | "authMethods" | "_meta"
        )
    }) {
        return Err(protocol_mismatch());
    }
    match result.remove("protocolVersion") {
        Some(Value::Number(version)) if version.as_u64() == Some(1) => {}
        Some(Value::String(version)) if version == "1" => {}
        _ => return Err(protocol_mismatch()),
    }
    let agent_capabilities = result
        .remove("agentCapabilities")
        .ok_or_else(protocol_mismatch)?;
    validate_meta(&agent_capabilities)?;
    if let Some(agent_info) = result.remove("agentInfo") {
        validate_agent_info(agent_info)?;
    }
    if let Some(meta) = result.remove("_meta") {
        validate_meta(&meta)?;
    }
    let auth_methods = result
        .remove("authMethods")
        .and_then(|methods| methods.as_array().cloned())
        .ok_or_else(protocol_mismatch)?;
    if auth_methods.len() > MAX_AUTH_METHODS {
        return Err(protocol_mismatch());
    }
    if !result.is_empty() {
        return Err(protocol_mismatch());
    }

    let mut ids = HashSet::new();
    for method in auth_methods {
        let method = method.as_object().ok_or_else(protocol_mismatch)?;
        if method.len() != 3
            || !method
                .keys()
                .all(|key| matches!(key.as_str(), "id" | "name" | "description"))
        {
            return Err(protocol_mismatch());
        }
        for key in ["id", "name", "description"] {
            if !method
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty() && value.len() <= MAX_AUTH_METHOD_TEXT_BYTES)
            {
                return Err(protocol_mismatch());
            }
        }
        let id = method
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(protocol_mismatch)?;
        if !ids.insert(id.to_owned()) {
            return Err(protocol_mismatch());
        }
        if id == "xai.api_key" {
            return Err(protocol_mismatch());
        }
    }
    if ids.contains("cached_token") {
        Ok(InitializeOutcome::Authenticate)
    } else {
        Ok(InitializeOutcome::SignedOut)
    }
}

fn validate_agent_info(agent_info: Value) -> Result<(), AuthError> {
    let agent_info = agent_info.as_object().ok_or_else(protocol_mismatch)?;
    if agent_info
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "title" | "version"))
        || !agent_info
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty() && name.len() <= MAX_AUTH_METHOD_TEXT_BYTES)
    {
        return Err(protocol_mismatch());
    }
    if let Some(title) = agent_info.get("title")
        && !title
            .as_str()
            .is_some_and(|title| !title.is_empty() && title.len() <= MAX_AUTH_METHOD_TEXT_BYTES)
    {
        return Err(protocol_mismatch());
    }
    if let Some(version) = agent_info.get("version") {
        let version = version.as_str().ok_or_else(protocol_mismatch)?;
        if version != GROK_VERSION {
            return Err(AuthError::from_code(AuthErrorCode::UnsupportedVersion));
        }
    }
    Ok(())
}

fn validate_authenticate_result(result: Value) -> Result<(), AuthError> {
    let mut result = into_object(result)?;
    if result.len() > 1 {
        return Err(protocol_mismatch());
    }
    if let Some(meta) = result.remove("_meta") {
        validate_meta(&meta)?;
    }
    if result.is_empty() {
        Ok(())
    } else {
        Err(protocol_mismatch())
    }
}

fn validate_meta(meta: &Value) -> Result<(), AuthError> {
    if !meta.is_object()
        || serde_json::to_vec(meta)
            .map_err(|_| protocol_mismatch())?
            .len()
            > MAX_META_BYTES
    {
        return Err(protocol_mismatch());
    }
    let mut nodes = 0;
    validate_meta_node(meta, 0, &mut nodes)
}

fn validate_meta_node(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), AuthError> {
    if depth > MAX_META_DEPTH {
        return Err(protocol_mismatch());
    }
    *nodes = nodes.checked_add(1).ok_or_else(protocol_mismatch)?;
    if *nodes > MAX_META_NODES {
        return Err(protocol_mismatch());
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) if value.len() <= MAX_META_STRING_BYTES => Ok(()),
        Value::String(_) => Err(protocol_mismatch()),
        Value::Array(values) if values.len() <= MAX_META_CONTAINER_ITEMS => {
            for value in values {
                validate_meta_node(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) if values.len() <= MAX_META_CONTAINER_ITEMS => {
            for (key, value) in values {
                if key.len() > MAX_META_STRING_BYTES {
                    return Err(protocol_mismatch());
                }
                validate_meta_node(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Array(_) | Value::Object(_) => Err(protocol_mismatch()),
    }
}

fn into_object(value: Value) -> Result<Map<String, Value>, AuthError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(protocol_mismatch()),
    }
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

fn timed_out() -> AuthError {
    AuthError::from_code(AuthErrorCode::TimedOut)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::sidecar::{ProviderEnvironmentProfile, authorize_test_foreground};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    const FIXTURE_SCRIPT: &str = r#"#!/bin/sh
set -u
IFS= read -r scenario < "$GROK_HOME/fixture-scenario"
printf '%s\n' "$*" >> "$GROK_HOME/argv.log"

if [ "$*" = "--no-auto-update version" ]; then
  if [ "$scenario" = "version-hang" ]; then
    /bin/sleep 60 &
    child=$!
    printf '%s %s\n' "$$" "$child" > "$GROK_HOME/fixture-pids"
    wait "$child"
    exit $?
  fi
  printf '%s\n' "Grok Build CLI release 0.2.111 (stable)"
  exit 0
fi

if [ "$*" = "--no-auto-update agent stdio" ]; then
  IFS= read -r initialize || exit 74
  printf '%s\n' "$initialize" >> "$GROK_HOME/requests.log"
  printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{},"agentInfo":{"name":"grok-build","title":"Grok Build","version":"0.2.111"},"authMethods":[{"id":"cached_token","name":"Cached token","description":"Provider managed"}]}}'
  IFS= read -r authenticate || exit 74
  printf '%s\n' "$authenticate" >> "$GROK_HOME/requests.log"
  if [ "$scenario" = "reconcile-hang" ]; then
    /bin/sleep 60 &
    child=$!
    printf '%s %s\n' "$$" "$child" > "$GROK_HOME/reconcile-pids"
    : > "$GROK_HOME/reconcile-started"
    wait "$child"
    exit $?
  fi
  if [ -f "$GROK_HOME/fixture-login-complete" ]; then
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
  else
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"signed out"}}'
  fi
  exit 0
fi

if [ "$*" = "--no-auto-update login" ] || [ "$*" = "--no-auto-update login --device-auth" ]; then
  if [ "$scenario" = "login-hang" ]; then
    /bin/sleep 60 &
    child=$!
    printf '%s %s\n' "$$" "$child" > "$GROK_HOME/fixture-pids"
    wait "$child"
    exit $?
  fi
  if [ "$scenario" = "login-decline" ]; then
    exit 19
  fi
  umask 077
  printf '%s' 'Bearer unit-test-secret' > "$GROK_HOME/auth.json"
  : > "$GROK_HOME/fixture-login-complete"
  if [ "$scenario" = "login-unsafe" ]; then
    /bin/chmod 0644 "$GROK_HOME/auth.json"
  fi
  exit 0
fi

if [ "$*" = "--no-auto-update logout" ]; then
  if [ "$scenario" = "logout-unsafe" ]; then
    /bin/chmod 0644 "$GROK_HOME/auth.json"
  elif [ "$scenario" != "logout-still-signed-in" ]; then
    /bin/rm -f "$GROK_HOME/auth.json" "$GROK_HOME/fixture-login-complete"
  fi
  if [ "$scenario" = "logout-decline" ]; then
    exit 19
  fi
  exit 0
fi

exit 64
"#;

    struct LocalFixture {
        broker: GrokAuth,
        executable: TrustedExecutable,
        root: PathBuf,
        data: PathBuf,
        workspace: PathBuf,
        home: PathBuf,
        request_timeout: Duration,
    }

    impl LocalFixture {
        async fn new(
            scenario: &str,
            initially_signed_in: bool,
            request_timeout: Duration,
            foreground_timeout: Duration,
        ) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            // Executable trust validates every ancestor; Linux's system temp
            // directory is intentionally world-writable.
            let root = std::env::current_exe()
                .expect("the Grok unit-test executable has a path")
                .parent()
                .expect("the Grok unit-test executable has a parent")
                .join(format!(
                    "carl-grok-auth-unit-{}-{serial}",
                    std::process::id()
                ));
            let data = root.join("data");
            let workspace = root.join("workspace");
            let home_path = data.join("providers").join("grok");
            let bin = root.join("bin");
            fs::create_dir_all(&data).expect("fixture data root is created");
            fs::create_dir_all(&workspace).expect("fixture workspace is created");
            fs::create_dir_all(&bin).expect("fixture bin is created");
            for directory in [&root, &data, &workspace, &bin] {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("fixture directory is private");
            }
            let executable_path = bin.join("grok");
            fs::write(&executable_path, FIXTURE_SCRIPT).expect("fixture script is written");
            fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
                .expect("fixture script is executable");
            let executable = TrustedExecutable::for_test(
                fs::canonicalize(&executable_path).expect("fixture executable canonicalizes"),
            );
            let home = ProviderHome::prepare(
                ProviderEnvironmentProfile::Grok,
                &data,
                &workspace,
                &home_path,
            )
            .expect("fixture provider home is prepared");
            home.write_static_file("fixture-scenario", scenario.as_bytes())
                .expect("fixture scenario is written");
            if initially_signed_in {
                home.write_static_file("auth.json", b"Bearer unit-test-secret")
                    .expect("fixture credential metadata is safe");
                home.write_static_file("fixture-login-complete", b"complete")
                    .expect("fixture login marker is written");
            }
            let broker = GrokAuth::connect_local(
                &executable,
                home,
                test_limits(),
                GrokAuthTimeouts::new(request_timeout, foreground_timeout),
                authorize_test_foreground(),
            )
            .await
            .expect("local Grok fixture connects");
            Self {
                broker,
                executable,
                root,
                data,
                workspace,
                home: home_path,
                request_timeout,
            }
        }

        async fn status_broker(&self) -> GrokAuth {
            let home = ProviderHome::prepare(
                ProviderEnvironmentProfile::Grok,
                &self.data,
                &self.workspace,
                &self.home,
            )
            .expect("the shared provider home is prepared");
            GrokAuth::connect(
                &self.executable,
                home,
                test_limits(),
                GrokAuthTimeouts::new(self.request_timeout, Duration::from_secs(2)),
            )
            .await
            .expect("the status broker connects")
        }

        fn set_scenario(&self, scenario: &str) {
            let path = self.home.join("fixture-scenario");
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .expect("fixture scenario opens");
            file.write_all(scenario.as_bytes())
                .expect("fixture scenario writes");
            file.sync_all().expect("fixture scenario syncs");
        }

        fn argv(&self) -> Vec<String> {
            fs::read_to_string(self.home.join("argv.log"))
                .expect("fixture argv log exists")
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_limits() -> SidecarLimits {
        SidecarLimits {
            max_stdout_line_bytes: 8 * 1024,
            max_stderr_bytes: 128,
            graceful_shutdown_timeout: Duration::from_millis(100),
            forced_shutdown_timeout: Duration::from_secs(1),
            process_poll_interval: Duration::from_millis(10),
        }
    }

    #[tokio::test]
    async fn local_login_and_logout_reconcile_only_through_acp() {
        let mut browser = LocalFixture::new(
            "normal",
            false,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(
            browser
                .broker
                .start_login(AuthMethod::BrowserOAuth)
                .await
                .expect("browser login succeeds"),
            LoginChallenge::ProviderManaged
        );
        assert_eq!(
            browser.broker.cached_state(),
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: None,
            }
        );
        assert_eq!(
            browser.argv(),
            [
                "--no-auto-update version",
                "--no-auto-update agent stdio",
                "--no-auto-update login",
                "--no-auto-update agent stdio",
            ]
        );

        let mut device = LocalFixture::new(
            "normal",
            false,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(
            device
                .broker
                .start_login(AuthMethod::DeviceCode)
                .await
                .expect("device login succeeds"),
            LoginChallenge::ProviderManaged
        );
        assert!(
            device
                .argv()
                .contains(&"--no-auto-update login --device-auth".to_owned())
        );
        assert_eq!(
            device
                .argv()
                .iter()
                .filter(|arguments| arguments.as_str() == "--no-auto-update version")
                .count(),
            1,
            "the verified broker never reruns the version child"
        );

        let mut declined = LocalFixture::new(
            "login-decline",
            false,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        let error = declined
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("a signed-out post-login probe is rejected");
        assert_eq!(error.code(), AuthErrorCode::ProviderRejected);
        assert_eq!(declined.broker.cached_state(), AuthState::SignedOut);

        let mut unsafe_login = LocalFixture::new(
            "login-unsafe",
            false,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        let error = unsafe_login
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("unsafe post-login credential metadata is rejected");
        assert_eq!(error.code(), AuthErrorCode::UnsafeCredentialStore);

        let mut logout = LocalFixture::new(
            "normal",
            true,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        logout
            .broker
            .logout()
            .await
            .expect("logout trusts the signed-out ACP result");
        assert_eq!(logout.broker.cached_state(), AuthState::SignedOut);
        assert!(
            logout
                .argv()
                .contains(&"--no-auto-update logout".to_owned())
        );

        let mut declined_logout = LocalFixture::new(
            "logout-decline",
            true,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        declined_logout
            .broker
            .logout()
            .await
            .expect("nonzero logout is accepted when ACP reports signed out");

        let mut ineffective_logout = LocalFixture::new(
            "logout-still-signed-in",
            true,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        let error = ineffective_logout
            .broker
            .logout()
            .await
            .expect_err("logout remaining signed in is rejected");
        assert_eq!(error.code(), AuthErrorCode::ProviderRejected);

        let mut unsafe_logout = LocalFixture::new(
            "logout-unsafe",
            true,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await;
        let error = unsafe_logout
            .broker
            .logout()
            .await
            .expect_err("unsafe post-logout credential metadata is rejected");
        assert_eq!(error.code(), AuthErrorCode::UnsafeCredentialStore);
    }

    #[tokio::test]
    async fn timeout_and_drop_after_spawn_reap_and_reconcile() {
        let mut timed_out = LocalFixture::new(
            "login-hang",
            false,
            Duration::from_millis(250),
            Duration::from_millis(100),
        )
        .await;
        let error = timed_out
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("hanging login times out");
        assert_eq!(error.code(), AuthErrorCode::TimedOut);
        assert_eq!(timed_out.broker.cached_state(), AuthState::SignedOut);
        let timeout_pids = read_pids(&timed_out.home.join("fixture-pids"));
        wait_for_processes_exit(&timeout_pids).await;

        let mut dropped = LocalFixture::new(
            "normal",
            false,
            Duration::from_millis(120),
            Duration::from_secs(5),
        )
        .await;
        let mut second = dropped.status_broker().await;
        dropped.set_scenario("login-hang");
        let mut login = dropped.broker.start_login(AuthMethod::BrowserOAuth);
        wait_for_file_while_pending(&mut login, &dropped.home.join("fixture-pids")).await;
        drop(login);
        assert_eq!(
            dropped
                .broker
                .auth_state()
                .await
                .expect("dropped login remains pending"),
            AuthState::Pending
        );
        let blocked = second
            .auth_state()
            .await
            .expect_err("the shared-home guard remains held until cancellation");
        assert_eq!(blocked.code(), AuthErrorCode::TimedOut);
        let dropped_pids = read_pids(&dropped.home.join("fixture-pids"));
        dropped
            .broker
            .cancel_login()
            .await
            .expect("cancel reaps and reconciles a dropped login");
        assert_eq!(dropped.broker.cached_state(), AuthState::SignedOut);
        dropped
            .broker
            .cancel_login()
            .await
            .expect("cancel is idempotent");
        wait_for_processes_exit(&dropped_pids).await;
        second
            .auth_state()
            .await
            .expect("shared-home status resumes after cancellation");
    }

    #[tokio::test]
    async fn pre_spawn_failure_releases_but_drop_during_reconcile_retains_lock() {
        let mut preflight = LocalFixture::new(
            "normal",
            false,
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .await;
        let mut second = preflight.status_broker().await;
        fs::write(preflight.home.join("auth.json"), b"Bearer unit-test-secret")
            .expect("unsafe fixture credential is written");
        fs::set_permissions(
            preflight.home.join("auth.json"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("fixture credential is made unsafe");
        let error = preflight
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("unsafe pre-spawn credential metadata is rejected");
        assert_eq!(error.code(), AuthErrorCode::UnsafeCredentialStore);
        fs::set_permissions(
            preflight.home.join("auth.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("fixture credential metadata is repaired");
        second
            .auth_state()
            .await
            .expect("a synchronous pre-spawn failure releases the local guard");
        preflight
            .broker
            .cancel_login()
            .await
            .expect("pre-spawn failure leaves no ceremony to cancel");

        let mut reconciliation = LocalFixture::new(
            "normal",
            false,
            Duration::from_millis(120),
            Duration::from_secs(5),
        )
        .await;
        let mut other = reconciliation.status_broker().await;
        reconciliation.set_scenario("reconcile-hang");
        let mut login = reconciliation.broker.start_login(AuthMethod::BrowserOAuth);
        wait_for_file_while_pending(&mut login, &reconciliation.home.join("reconcile-started"))
            .await;
        let reconciliation_pids = read_pids(&reconciliation.home.join("reconcile-pids"));
        drop(login);
        let blocked = other
            .auth_state()
            .await
            .expect_err("reconciliation drop retains the shared-home guard");
        assert_eq!(blocked.code(), AuthErrorCode::TimedOut);
        reconciliation.set_scenario("normal");
        reconciliation
            .broker
            .cancel_login()
            .await
            .expect("cancel reruns dropped reconciliation");
        assert_eq!(
            reconciliation.broker.cached_state(),
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: None,
            }
        );
        wait_for_processes_exit(&reconciliation_pids).await;
        other
            .auth_state()
            .await
            .expect("shared-home status resumes after reconciliation");
    }

    async fn wait_for_file_while_pending(future: &mut AuthFuture<'_, LoginChallenge>, path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::select! {
                result = future.as_mut() => {
                    panic!("foreground operation completed before fixture marker: {result:?}");
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            if path.exists() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fixture marker was not created: {}",
                path.display()
            );
        }
    }

    fn read_pids(path: &Path) -> Vec<u32> {
        fs::read_to_string(path)
            .expect("fixture PID file exists")
            .split_ascii_whitespace()
            .map(|pid| pid.parse().expect("fixture PID is numeric"))
            .collect()
    }

    async fn wait_for_processes_exit(pids: &[u32]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if pids.iter().all(|pid| !process_is_alive(*pid)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fixture processes remain alive: {pids:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn process_is_alive(pid: u32) -> bool {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: signal zero checks process existence without signaling it.
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return false;
        }
        std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .is_ok_and(|output| {
                if !output.status.success() {
                    return false;
                }
                let state = String::from_utf8_lossy(&output.stdout);
                !state.trim().is_empty() && !state.trim_start().starts_with('Z')
            })
    }
}
