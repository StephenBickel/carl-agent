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
                request_id: "client-negotiate-v1".to_owned(),
                idempotency_key: "client-negotiate-v1".to_owned(),
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
        || info.models.len() > 128
        || !info.capabilities.durable_events
        || !info.capabilities.reconnect
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
        models: Vec::new(),
        default_model: None,
        default_effort: None,
        capabilities: super::protocol::ServiceCapabilities {
            durable_events: false,
            reconnect: false,
            trusted_buzz_admission: false,
            configure_active_task: false,
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
    let (reader, writer) = tokio::io::split(client);
    Ok((Box::pin(reader), Box::pin(writer)))
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
