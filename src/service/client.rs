use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;

use thiserror::Error;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
};

use super::protocol::{
    MAX_SERVICE_FRAME_BYTES, SERVICE_PROTOCOL_VERSION, ServiceCommand, ServiceFrame, ServiceInfo,
    ServiceRequest, ServiceResult, decode_frame_line, encode_request,
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
#[cfg(unix)]
use tokio::net::UnixStream;

type LocalReader = Pin<Box<dyn AsyncRead + Send>>;
type LocalWriter = Pin<Box<dyn AsyncWrite + Send>>;

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
struct WindowsPipeAceShape {
    allow: bool,
    inherited: bool,
    mask: u32,
    current_user: bool,
}

#[cfg(any(windows, test))]
fn valid_windows_pipe_security_shape(
    owner_is_current_user: bool,
    dacl_protected: bool,
    aces: &[WindowsPipeAceShape],
) -> bool {
    owner_is_current_user
        && dacl_protected
        && matches!(
            aces,
            [WindowsPipeAceShape {
                allow: true,
                inherited: false,
                mask: super::server::WINDOWS_PIPE_ACCESS,
                current_user: true,
            }]
        )
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceClientErrorCode {
    #[error("the Carl service endpoint identity is invalid")]
    InvalidEndpoint,
    #[error("the Carl service is unavailable")]
    Unavailable,
    #[error("the Carl service rejected the request")]
    Rejected,
    #[error("the Carl service response is invalid")]
    InvalidResponse,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct ServiceClientError {
    code: ServiceClientErrorCode,
}

impl ServiceClientError {
    #[must_use]
    pub const fn code(&self) -> ServiceClientErrorCode {
        self.code
    }
}

pub struct TaskServiceClient {
    data_root: PathBuf,
    reader: BufReader<LocalReader>,
    writer: LocalWriter,
    last_event_cursor: Option<u64>,
    info: ServiceInfo,
}

impl TaskServiceClient {
    pub async fn connect(data_root: impl AsRef<Path>) -> Result<Self, ServiceClientError> {
        Self::connect_with_cursor(data_root, None).await
    }

    pub async fn connect_with_cursor(
        data_root: impl AsRef<Path>,
        last_event_cursor: Option<u64>,
    ) -> Result<Self, ServiceClientError> {
        let data_root = std::fs::canonicalize(data_root.as_ref())
            .map_err(|_| client_error(ServiceClientErrorCode::InvalidEndpoint))?;
        let (reader, writer) = connect_verified(&data_root).await?;
        let mut client = Self {
            data_root,
            reader: BufReader::new(reader),
            writer,
            last_event_cursor,
            info: empty_info(),
        };
        client.negotiate().await?;
        Ok(client)
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        SERVICE_PROTOCOL_VERSION
    }

    #[must_use]
    pub const fn last_event_cursor(&self) -> Option<u64> {
        self.last_event_cursor
    }

    #[must_use]
    pub const fn info(&self) -> &ServiceInfo {
        &self.info
    }

    pub async fn request(
        &mut self,
        request: ServiceRequest,
    ) -> Result<ServiceResult, ServiceClientError> {
        match self.request_once(&request).await {
            Ok(result) => Ok(result),
            Err(error) if error.code() == ServiceClientErrorCode::Unavailable => {
                self.reconnect().await?;
                self.request_once(&request).await
            }
            Err(error) => Err(error),
        }
    }

    async fn request_once(
        &mut self,
        request: &ServiceRequest,
    ) -> Result<ServiceResult, ServiceClientError> {
        let encoded = encode_request(request)
            .map_err(|_| client_error(ServiceClientErrorCode::InvalidResponse))?;
        self.writer
            .write_all(&encoded)
            .await
            .map_err(|_| client_error(ServiceClientErrorCode::Unavailable))?;
        self.writer
            .flush()
            .await
            .map_err(|_| client_error(ServiceClientErrorCode::Unavailable))?;
        let line = read_bounded_line(&mut self.reader).await?;
        let frame = decode_frame_line(&line)
            .map_err(|_| client_error(ServiceClientErrorCode::InvalidResponse))?;
        match frame {
            ServiceFrame::Response { request_id, result } if request_id == request.request_id => {
                if let ServiceResult::Events(events) = result.as_ref()
                    && let Some(sequence) = events.last().map(|event| event.sequence)
                {
                    self.last_event_cursor = Some(sequence);
                }
                Ok(*result)
            }
            ServiceFrame::Error { request_id, .. } if request_id == request.request_id => {
                Err(client_error(ServiceClientErrorCode::Rejected))
            }
            ServiceFrame::Response { .. }
            | ServiceFrame::Error { .. }
            | ServiceFrame::Event { .. } => {
                Err(client_error(ServiceClientErrorCode::InvalidResponse))
            }
        }
    }

    async fn reconnect(&mut self) -> Result<(), ServiceClientError> {
        let (reader, writer) = connect_verified(&self.data_root).await?;
        self.reader = BufReader::new(reader);
        self.writer = writer;
        self.negotiate().await
    }

    async fn negotiate(&mut self) -> Result<(), ServiceClientError> {
        let result = self
            .request_once(&ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "client-negotiate-v2".to_owned(),
                idempotency_key: "client-negotiate-v2".to_owned(),
                command: ServiceCommand::Info,
            })
            .await?;
        let ServiceResult::Info(info) = result else {
            return Err(client_error(ServiceClientErrorCode::InvalidResponse));
        };
        validate_info(&info)?;
        self.info = info;
        Ok(())
    }
}

fn validate_info(info: &ServiceInfo) -> Result<(), ServiceClientError> {
    if info.protocol_version != SERVICE_PROTOCOL_VERSION
        || uuid::Uuid::parse_str(&info.live_generation).is_err()
        || info.models.len() > 128
        || !info.capabilities.durable_events
        || !info.capabilities.reconnect
        || !info.capabilities.explicit_task_budgets
    {
        return Err(client_error(ServiceClientErrorCode::InvalidResponse));
    }
    let mut ids = std::collections::BTreeSet::new();
    for model in &info.models {
        if !ids.insert(model.id.as_str())
            || model.display_name.is_empty()
            || model.display_name.len() > 256
            || model.display_name.chars().any(char::is_control)
            || model.supported_efforts.is_empty()
            || model.supported_efforts.len() > 6
            || !model.supported_efforts.contains(&model.default_effort)
        {
            return Err(client_error(ServiceClientErrorCode::InvalidResponse));
        }
    }
    match (&info.default_model, info.default_effort) {
        (Some(model), Some(effort))
            if info.models.iter().any(|candidate| {
                candidate.id == *model && candidate.supported_efforts.contains(&effort)
            }) => {}
        (None, None) if info.models.is_empty() => {}
        _ => return Err(client_error(ServiceClientErrorCode::InvalidResponse)),
    }
    Ok(())
}

fn empty_info() -> ServiceInfo {
    ServiceInfo {
        protocol_version: 0,
        live_generation: String::new(),
        models: Vec::new(),
        default_model: None,
        default_effort: None,
        capabilities: super::protocol::ServiceCapabilities {
            durable_events: false,
            reconnect: false,
            trusted_buzz_admission: false,
            configure_active_task: false,
            explicit_task_budgets: false,
        },
    }
}

#[cfg(unix)]
async fn connect_verified(
    data_root: &Path,
) -> Result<(LocalReader, LocalWriter), ServiceClientError> {
    let socket_path = data_root.join("carl.sock");
    let metadata = std::fs::symlink_metadata(&socket_path)
        .map_err(|_| client_error(ServiceClientErrorCode::Unavailable))?;
    if !metadata.file_type().is_socket()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }
    let stream = UnixStream::connect(&socket_path)
        .await
        .map_err(|_| client_error(ServiceClientErrorCode::Unavailable))?;
    let (reader, writer) = stream.into_split();
    Ok((Box::pin(reader), Box::pin(writer)))
}

#[cfg(windows)]
async fn connect_verified(
    data_root: &Path,
) -> Result<(LocalReader, LocalWriter), ServiceClientError> {
    use std::os::windows::io::AsRawHandle as _;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let pipe_name = super::server::windows_pipe_name(data_root);
    let mut attempts = 0_u8;
    let client = loop {
        match ClientOptions::new().open(&pipe_name) {
            Ok(client) => break client,
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempts < 20 => {
                attempts = attempts.saturating_add(1);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(_) => return Err(client_error(ServiceClientErrorCode::Unavailable)),
        }
    };
    verify_windows_pipe_server(client.as_raw_handle().cast())?;
    let (reader, writer) = tokio::io::split(client);
    Ok((Box::pin(reader), Box::pin(writer)))
}

#[cfg(windows)]
fn verify_windows_pipe_server(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), ServiceClientError> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_ACE_TYPE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        EqualSid, GetAce, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let current = current_process_user_sid()?;
    let mut server_pid = 0_u32;
    // SAFETY: pipe is a connected named-pipe client handle and server_pid is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) } == 0 {
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }
    // SAFETY: the requested access is query-only and server_pid came from the pipe kernel object.
    let server_process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
    if server_process.is_null() {
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }
    let server = process_user_sid(server_process);
    // SAFETY: server_process is an owned process handle from OpenProcess.
    unsafe { CloseHandle(server_process) };
    let server = server?;
    // SAFETY: both token buffers remain live and contain validated TOKEN_USER SIDs.
    if unsafe { EqualSid(current.sid(), server.sid()) } == 0 {
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: all requested output pointers are writable and descriptor is freed below.
    let security = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if security != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        if !descriptor.is_null() {
            // SAFETY: descriptor was allocated by GetSecurityInfo.
            unsafe { LocalFree(descriptor) };
        }
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is live and both outputs are writable.
    let protected = unsafe {
        GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
            && u32::from(control) & SE_DACL_PROTECTED != 0
    };
    // SAFETY: owner and current SID remain live.
    let owner_matches = unsafe { EqualSid(owner, current.sid()) != 0 };
    // Exactly one current-user allow ACE with the intended read/write mask prevents a
    // permissive, inherited, or foreign pre-created pipe.
    // SAFETY: dacl is non-null and remains owned by descriptor until LocalFree below.
    let ace_count = unsafe { (*dacl).AceCount };
    let private_dacl = if ace_count == 1 {
        let mut ace = std::ptr::null_mut();
        // SAFETY: dacl is live and advertises exactly one ACE.
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
            false
        } else {
            // SAFETY: GetAce returned a live ACE_HEADER and the declared allow
            // ACE layout contains its mask and SID.
            let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
            let allow = header.AceType == ACCESS_ALLOWED_ACE_TYPE;
            let (mask, current_user) = if allow {
                // SAFETY: the ACE type is ACCESS_ALLOWED_ACE and SidStart begins its SID.
                let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
                let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
                // SAFETY: both SIDs remain live for the comparison.
                (allowed.Mask, unsafe { EqualSid(sid, current.sid()) != 0 })
            } else {
                (0, false)
            };
            valid_windows_pipe_security_shape(
                owner_matches,
                protected,
                &[WindowsPipeAceShape {
                    allow,
                    inherited: header.AceFlags != 0,
                    mask,
                    current_user,
                }],
            )
        }
    } else {
        false
    };
    // SAFETY: descriptor was allocated by GetSecurityInfo and is no longer used.
    unsafe { LocalFree(descriptor) };
    if private_dacl {
        Ok(())
    } else {
        Err(client_error(ServiceClientErrorCode::InvalidEndpoint))
    }
}

#[cfg(windows)]
struct TokenUserBuffer(Vec<usize>);

#[cfg(windows)]
impl TokenUserBuffer {
    fn sid(&self) -> windows_sys::Win32::Security::PSID {
        use windows_sys::Win32::Security::TOKEN_USER;
        // SAFETY: process_user_sid filled this aligned buffer with TOKEN_USER.
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

#[cfg(windows)]
fn current_process_user_sid() -> Result<TokenUserBuffer, ServiceClientError> {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: GetCurrentProcess returns a process pseudo-handle valid in this process.
    process_user_sid(unsafe { GetCurrentProcess() })
}

#[cfg(windows)]
fn process_user_sid(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<TokenUserBuffer, ServiceClientError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let mut token = std::ptr::null_mut();
    // SAFETY: process is queryable and token is a writable output pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }
    let mut bytes = 0_u32;
    // SAFETY: the first call intentionally queries the required buffer size.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes) };
    let words = usize::try_from(bytes)
        .map_err(|_| client_error(ServiceClientErrorCode::InvalidEndpoint))?
        .div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // SAFETY: buffer is aligned and at least bytes long; token and output remain live.
    let loaded = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    };
    // SAFETY: token is owned by this function and no longer used.
    unsafe { CloseHandle(token) };
    if loaded == 0 || bytes < u32::try_from(std::mem::size_of::<TOKEN_USER>()).unwrap_or(u32::MAX) {
        return Err(client_error(ServiceClientErrorCode::InvalidEndpoint));
    }
    Ok(TokenUserBuffer(buffer))
}

async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ServiceClientError> {
    let mut line = Vec::new();
    let read = reader
        .take((MAX_SERVICE_FRAME_BYTES + 2) as u64)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| client_error(ServiceClientErrorCode::Unavailable))?;
    if read == 0 {
        return Err(client_error(ServiceClientErrorCode::Unavailable));
    }
    if line.len() > MAX_SERVICE_FRAME_BYTES + 1 || line.last() != Some(&b'\n') {
        return Err(client_error(ServiceClientErrorCode::InvalidResponse));
    }
    Ok(line)
}

const fn client_error(code: ServiceClientErrorCode) -> ServiceClientError {
    ServiceClientError { code }
}

#[cfg(test)]
mod tests {
    use super::{
        ServiceClientErrorCode, WindowsPipeAceShape, valid_windows_pipe_security_shape,
        validate_info,
    };
    use crate::service::protocol::{SERVICE_PROTOCOL_VERSION, ServiceCapabilities, ServiceInfo};
    use crate::service::server::WINDOWS_PIPE_ACCESS;

    const LEGITIMATE: WindowsPipeAceShape = WindowsPipeAceShape {
        allow: true,
        inherited: false,
        mask: WINDOWS_PIPE_ACCESS,
        current_user: true,
    };

    fn info(explicit_task_budgets: bool) -> ServiceInfo {
        ServiceInfo {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            live_generation: "11111111-1111-4111-8111-111111111111".to_owned(),
            models: Vec::new(),
            default_model: None,
            default_effort: None,
            capabilities: ServiceCapabilities {
                durable_events: true,
                reconnect: true,
                trusted_buzz_admission: true,
                configure_active_task: true,
                explicit_task_budgets,
            },
        }
    }

    #[test]
    fn negotiation_requires_the_explicit_task_budget_capability() {
        validate_info(&info(true)).expect("advertised budget support is accepted");
        assert_eq!(
            validate_info(&info(false))
                .expect_err("false budget support must fail negotiation")
                .code(),
            ServiceClientErrorCode::InvalidResponse
        );

        let mut missing = serde_json::to_value(info(true)).unwrap();
        missing["capabilities"]
            .as_object_mut()
            .unwrap()
            .remove("explicit_task_budgets");
        assert!(
            serde_json::from_value::<ServiceInfo>(missing).is_err(),
            "missing budget capability must fail closed"
        );
    }

    #[test]
    fn windows_pipe_security_shape_rejects_every_non_private_variant() {
        assert!(valid_windows_pipe_security_shape(true, true, &[LEGITIMATE]));
        assert!(!valid_windows_pipe_security_shape(
            false,
            true,
            &[LEGITIMATE]
        ));
        assert!(!valid_windows_pipe_security_shape(
            true,
            false,
            &[LEGITIMATE]
        ));
        assert!(!valid_windows_pipe_security_shape(
            true,
            true,
            &[LEGITIMATE, LEGITIMATE]
        ));
        for ace in [
            WindowsPipeAceShape {
                allow: false,
                ..LEGITIMATE
            },
            WindowsPipeAceShape {
                inherited: true,
                ..LEGITIMATE
            },
            WindowsPipeAceShape {
                mask: WINDOWS_PIPE_ACCESS & !0x4000_0000,
                ..LEGITIMATE
            },
            WindowsPipeAceShape {
                mask: WINDOWS_PIPE_ACCESS | 0x1000_0000,
                ..LEGITIMATE
            },
            WindowsPipeAceShape {
                current_user: false,
                ..LEGITIMATE
            },
        ] {
            assert!(!valid_windows_pipe_security_shape(true, true, &[ace]));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn owner_pipe_created_for_the_current_user_passes_client_verification() {
        use std::os::windows::io::AsRawHandle as _;

        let pipe_name = format!(r"\\.\pipe\carl-contract-{}", uuid::Uuid::new_v4());
        let mut server = crate::service::server::create_owner_pipe(&pipe_name, true).unwrap();
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&pipe_name)
            .unwrap();
        server.connect().await.unwrap();
        super::verify_windows_pipe_server(client.as_raw_handle().cast()).unwrap();
    }
}
