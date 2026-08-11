use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::acp::PermissionMode;
use crate::events::TurnId;
use crate::policy::{Frontend, Sha256Digest};
use crate::runtime::agent_port::{AgentPort, EffectDecision};
use crate::runtime::task::{
    OwnerConfigureSession, OwnerStartTask, OwnerTrustedAdmission, OwnerTrustedMessage,
    TaskControlKind, TaskEngine, TaskEngineAcknowledgement, TaskEngineControl, TaskEngineError,
    TaskEngineErrorCode, TaskEngineUpdate, TaskId, TaskStatus,
};
use crate::sidecar::{DataRootLock, DataRootLockErrorCode};
use crate::storage::{RuntimeStore, ServiceCommandReceiptClaim, ServiceCommandReceiptInput, Store};

use super::protocol::{
    LiveUpdateEnvelope, LiveUpdatePage, MAX_SERVICE_FRAME_BYTES, ProtocolErrorCode, RequestLedger,
    ServiceCapabilities, ServiceCommand, ServiceFrame, ServiceInfo, ServiceModel, ServiceRequest,
    ServiceResult, ServiceSessionInfo, TaskUpdate, command_digest, decode_request_line,
    encode_frame, is_mutation,
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
#[cfg(unix)]
use tokio::net::UnixListener;

type LocalReader = Pin<Box<dyn AsyncRead + Send>>;
type LocalWriter = Pin<Box<dyn AsyncWrite + Send>>;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EndpointErrorCode {
    #[error("the Carl data root is already owned")]
    Contended,
    #[error("the Carl service endpoint entry is unsafe")]
    UnsafeEntry,
    #[error("the Carl service endpoint is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct EndpointError {
    code: EndpointErrorCode,
}

impl EndpointError {
    #[must_use]
    pub const fn code(&self) -> EndpointErrorCode {
        self.code
    }
}

#[cfg(unix)]
pub struct OwnedLocalEndpoint {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    data_root_lock: Option<DataRootLock>,
}

#[cfg(unix)]
impl OwnedLocalEndpoint {
    pub async fn bind(data_root: impl AsRef<Path>) -> Result<Self, EndpointError> {
        let data_root_lock = DataRootLock::acquire(data_root.as_ref()).map_err(|error| {
            endpoint_error(if error.code() == DataRootLockErrorCode::Contended {
                EndpointErrorCode::Contended
            } else {
                EndpointErrorCode::UnsafeEntry
            })
        })?;
        let socket_path = data_root_lock.runtime_data_root().join("carl.sock");
        match fs::symlink_metadata(&socket_path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                fs::remove_file(&socket_path)
                    .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?;
            }
            Ok(_) => return Err(endpoint_error(EndpointErrorCode::UnsafeEntry)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(endpoint_error(EndpointErrorCode::Unavailable)),
        }
        let listener = UnixListener::bind(&socket_path)
            .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?;
        if fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).is_err() {
            let _ = fs::remove_file(&socket_path);
            return Err(endpoint_error(EndpointErrorCode::Unavailable));
        }
        let metadata = fs::symlink_metadata(&socket_path)
            .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            let _ = fs::remove_file(&socket_path);
            return Err(endpoint_error(EndpointErrorCode::UnsafeEntry));
        }
        Ok(Self {
            listener,
            socket_path,
            socket_identity: (metadata.dev(), metadata.ino()),
            data_root_lock: Some(data_root_lock),
        })
    }

    #[must_use]
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    async fn accept(&mut self) -> Result<(LocalReader, LocalWriter), EndpointError> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?;
        let (reader, writer) = stream.into_split();
        Ok((Box::pin(reader), Box::pin(writer)))
    }

    pub(crate) fn take_data_root_lock(&mut self) -> Result<DataRootLock, EndpointError> {
        self.data_root_lock
            .take()
            .ok_or_else(|| endpoint_error(EndpointErrorCode::Unavailable))
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(unix)]
impl fmt::Debug for OwnedLocalEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedLocalEndpoint")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl Drop for OwnedLocalEndpoint {
    fn drop(&mut self) {
        let same_socket = fs::symlink_metadata(&self.socket_path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && (metadata.dev(), metadata.ino()) == self.socket_identity
        });
        if same_socket {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

#[cfg(windows)]
pub struct OwnedLocalEndpoint {
    pipe_name: String,
    next_server: tokio::net::windows::named_pipe::NamedPipeServer,
    data_root_lock: Option<DataRootLock>,
}

#[cfg(windows)]
impl OwnedLocalEndpoint {
    pub async fn bind(data_root: impl AsRef<Path>) -> Result<Self, EndpointError> {
        let data_root_lock = DataRootLock::acquire(data_root.as_ref()).map_err(|error| {
            endpoint_error(if error.code() == DataRootLockErrorCode::Contended {
                EndpointErrorCode::Contended
            } else {
                EndpointErrorCode::UnsafeEntry
            })
        })?;
        let pipe_name = windows_pipe_name(data_root_lock.runtime_data_root());
        let next_server = create_owner_pipe(&pipe_name, true)?;
        Ok(Self {
            pipe_name,
            next_server,
            data_root_lock: Some(data_root_lock),
        })
    }

    async fn accept(&mut self) -> Result<(LocalReader, LocalWriter), EndpointError> {
        self.next_server
            .connect()
            .await
            .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?;
        let replacement = create_owner_pipe(&self.pipe_name, false)?;
        let connected = std::mem::replace(&mut self.next_server, replacement);
        let (reader, writer) = tokio::io::split(connected);
        Ok((Box::pin(reader), Box::pin(writer)))
    }

    pub(crate) fn take_data_root_lock(&mut self) -> Result<DataRootLock, EndpointError> {
        self.data_root_lock
            .take()
            .ok_or_else(|| endpoint_error(EndpointErrorCode::Unavailable))
    }

    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

#[cfg(windows)]
impl fmt::Debug for OwnedLocalEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedLocalEndpoint")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
pub(crate) fn windows_pipe_name(data_root: &Path) -> String {
    use std::os::windows::ffi::OsStrExt as _;

    let mut hasher = Sha256::new();
    for unit in data_root.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    format!(r"\\.\pipe\carl-{:x}", hasher.finalize())
}

#[cfg(windows)]
fn create_owner_pipe(
    pipe_name: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, EndpointError> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let descriptor_string = std::ffi::OsStr::new("D:P(A;;GA;;;OW)")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the SDDL buffer is NUL-terminated and both output pointers remain
    // valid for the duration of the Windows conversion call.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_string.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        return Err(endpoint_error(EndpointErrorCode::Unavailable));
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `attributes` and its security descriptor are valid during pipe
    // creation. CreateNamedPipe copies the descriptor before returning.
    let created = unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&raw mut attributes).cast::<core::ffi::c_void>(),
        )
    };
    // SAFETY: the descriptor was allocated by ConvertStringSecurityDescriptor...
    // and has not been freed or aliased for ownership elsewhere.
    unsafe {
        let _ = LocalFree(descriptor);
    }
    created.map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))
}

const fn endpoint_error(code: EndpointErrorCode) -> EndpointError {
    EndpointError { code }
}

const SERVICE_COMMAND_CAPACITY: usize = 64;
const SERVICE_CONTROL_CAPACITY: usize = 64;
const LIVE_UPDATE_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskServiceErrorCode {
    #[error("the Carl service endpoint failed")]
    Endpoint,
    #[error("the Carl service durable state failed")]
    Storage,
    #[error("the Carl service task engine failed")]
    Engine,
    #[error("the Carl service transport failed")]
    Transport,
    #[error("the Carl service request is invalid")]
    InvalidRequest,
    #[error("the Carl service is busy")]
    Busy,
    #[error("the Carl service stopped")]
    Stopped,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct TaskServiceError {
    code: TaskServiceErrorCode,
}

impl TaskServiceError {
    #[must_use]
    pub const fn code(&self) -> TaskServiceErrorCode {
        self.code
    }
}

pub struct TaskService<P: AgentPort + 'static> {
    endpoint: OwnedLocalEndpoint,
    engine: TaskEngine<P, RuntimeStore>,
    read_store: Arc<Mutex<Store>>,
    initial_tasks: Vec<TaskId>,
    controls: mpsc::Sender<TaskEngineControl>,
    acknowledgements: Arc<tokio::sync::Mutex<mpsc::Receiver<TaskEngineAcknowledgement>>>,
    mutation_gate: Arc<tokio::sync::Mutex<()>>,
    live_updates: Arc<LiveUpdateHub>,
    live_update_receiver: mpsc::Receiver<(TaskId, TaskEngineUpdate)>,
    permission_receiver: mpsc::Receiver<crate::runtime::task::TaskEnginePermissionNotice>,
    next_acknowledgement: Arc<AtomicU64>,
    active_task: Arc<tokio::sync::Mutex<Option<TaskId>>>,
    info: ServiceInfo,
}

impl<P: AgentPort + 'static> fmt::Debug for TaskService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskService")
            .field("initial_tasks", &self.initial_tasks.len())
            .finish_non_exhaustive()
    }
}

impl<P: AgentPort + 'static> TaskService<P> {
    pub async fn bind(data_root: impl AsRef<Path>, mut port: P) -> Result<Self, TaskServiceError> {
        let mut endpoint = OwnedLocalEndpoint::bind(data_root)
            .await
            .map_err(|_| service_error(TaskServiceErrorCode::Endpoint))?;
        let data_root_lock = endpoint
            .take_data_root_lock()
            .map_err(|_| service_error(TaskServiceErrorCode::Endpoint))?;
        let runtime_store = RuntimeStore::open(data_root_lock, Utc::now())
            .map_err(|_| service_error(TaskServiceErrorCode::Storage))?;
        let read_store = Arc::new(Mutex::new(
            runtime_store
                .open_peer_store()
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?,
        ));
        let info = service_info(
            port.models()
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Engine))?,
        )?;
        let mut engine = TaskEngine::new_runtime(runtime_store, port);
        let initial_tasks = engine.reconcile_startup().await.map_err(map_engine)?;
        let (live_update_sender, live_update_receiver) = mpsc::channel(LIVE_UPDATE_CAPACITY);
        let live_update_overflow = Arc::new(AtomicU64::new(0));
        engine.install_update_sink(live_update_sender, Arc::clone(&live_update_overflow));
        let (controls, control_receiver) = mpsc::channel(SERVICE_CONTROL_CAPACITY);
        let (acknowledgement_sender, acknowledgement_receiver) =
            mpsc::channel(SERVICE_CONTROL_CAPACITY);
        let (permission_sender, permission_receiver) = mpsc::channel(1);
        engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);
        Ok(Self {
            endpoint,
            engine,
            read_store,
            initial_tasks,
            controls,
            acknowledgements: Arc::new(tokio::sync::Mutex::new(acknowledgement_receiver)),
            mutation_gate: Arc::new(tokio::sync::Mutex::new(())),
            live_updates: Arc::new(LiveUpdateHub::new(live_update_overflow)),
            live_update_receiver,
            permission_receiver,
            next_acknowledgement: Arc::new(AtomicU64::new(1)),
            active_task: Arc::new(tokio::sync::Mutex::new(None)),
            info,
        })
    }

    pub async fn serve(self, cancellation: CancellationToken) -> Result<(), TaskServiceError> {
        let Self {
            mut endpoint,
            engine,
            read_store,
            initial_tasks,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates,
            mut live_update_receiver,
            mut permission_receiver,
            next_acknowledgement,
            active_task,
            info,
        } = self;
        let (actor_sender, actor_receiver) = mpsc::channel(SERVICE_COMMAND_CAPACITY);
        let actor_active = Arc::clone(&active_task);
        let mut actor_task = AbortOnDrop::new(tokio::spawn(run_task_actor(
            engine,
            initial_tasks,
            actor_receiver,
            actor_active,
        )));
        let shared = Arc::new(ServiceShared {
            read_store,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates: Arc::clone(&live_updates),
            next_acknowledgement,
            active_task,
            actor_sender,
            info,
        });
        let live_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    update = live_update_receiver.recv() => {
                        let Some(update) = update else { break };
                        if let Some((task_id, update)) = map_live_update(update) {
                            live_updates.publish(task_id, update);
                        }
                    }
                    notice = permission_receiver.recv() => {
                        let Some(notice) = notice else { break };
                        live_updates.publish(
                            notice.task_id,
                            TaskUpdate::ApprovalRequired {
                                task_id: notice.task_id,
                                operation_id: notice.operation_id,
                                display_code: notice.display_code,
                                summary: notice.summary,
                                request_id: notice.request_id,
                                session_id: notice.session_id,
                                turn_id: notice.turn_id,
                                external_session_id: notice.external_session_id.as_str().to_owned(),
                            },
                        );
                    }
                }
            }
        });
        let stop = CancellationToken::new();
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    shutdown_owner(&shared).await?;
                    break;
                }
                () = stop.cancelled() => break,
                accepted = endpoint.accept() => {
                    let (reader, writer) = accepted
                        .map_err(|_| service_error(TaskServiceErrorCode::Transport))?;
                    let shared = Arc::clone(&shared);
                    let stop = stop.clone();
                    connections.spawn(async move {
                        handle_connection(reader, writer, shared, stop).await
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        drop(shared);
        live_task.abort();
        let _ = live_task.await;
        actor_task
            .join()
            .await
            .map_err(|_| service_error(TaskServiceErrorCode::Stopped))??;
        drop(endpoint);
        Ok(())
    }
}

struct AbortOnDrop<T> {
    task: Option<tokio::task::JoinHandle<T>>,
}

impl<T> AbortOnDrop<T> {
    const fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn join(&mut self) -> Result<T, tokio::task::JoinError> {
        self.task.take().expect("actor task is joined once").await
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct ServiceShared {
    read_store: Arc<Mutex<Store>>,
    controls: mpsc::Sender<TaskEngineControl>,
    acknowledgements: Arc<tokio::sync::Mutex<mpsc::Receiver<TaskEngineAcknowledgement>>>,
    mutation_gate: Arc<tokio::sync::Mutex<()>>,
    live_updates: Arc<LiveUpdateHub>,
    next_acknowledgement: Arc<AtomicU64>,
    active_task: Arc<tokio::sync::Mutex<Option<TaskId>>>,
    actor_sender: mpsc::Sender<ActorCommand>,
    info: ServiceInfo,
}

struct LiveUpdateHub {
    tasks: Mutex<HashMap<TaskId, LiveTaskUpdates>>,
    source_overflow: Arc<AtomicU64>,
}

struct LiveTaskUpdates {
    next_cursor: u64,
    ring: VecDeque<LiveUpdateEnvelope>,
    subscribers: Vec<mpsc::Sender<LiveUpdateEnvelope>>,
    observed_source_overflow: u64,
    pending_approval: Option<LiveUpdateEnvelope>,
}

impl Default for LiveTaskUpdates {
    fn default() -> Self {
        Self {
            next_cursor: 1,
            ring: VecDeque::new(),
            subscribers: Vec::new(),
            observed_source_overflow: 0,
            pending_approval: None,
        }
    }
}

impl LiveUpdateHub {
    fn new(source_overflow: Arc<AtomicU64>) -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            source_overflow,
        }
    }

    fn publish(&self, task_id: TaskId, update: TaskUpdate) {
        let Ok(mut tasks) = self.tasks.lock() else {
            return;
        };
        let task = tasks.entry(task_id).or_default();
        let envelope = LiveUpdateEnvelope {
            cursor: task.next_cursor,
            update,
        };
        if matches!(&envelope.update, TaskUpdate::ApprovalRequired { .. }) {
            task.pending_approval = Some(envelope.clone());
        }
        task.next_cursor = task.next_cursor.saturating_add(1);
        if task.ring.len() == LIVE_UPDATE_CAPACITY {
            task.ring.pop_front();
        }
        task.ring.push_back(envelope.clone());
        task.subscribers
            .retain(|subscriber| subscriber.try_send(envelope.clone()).is_ok());
    }

    fn clear_pending_approval(&self, task_id: TaskId) {
        if let Ok(mut tasks) = self.tasks.lock()
            && let Some(task) = tasks.get_mut(&task_id)
        {
            task.pending_approval = None;
        }
    }

    async fn page(
        &self,
        task_id: TaskId,
        after_cursor: Option<u64>,
        limit: u16,
    ) -> Result<(Vec<LiveUpdateEnvelope>, Option<u64>, bool), TaskServiceError> {
        let (initial, receiver) = {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
            let task = tasks.entry(task_id).or_default();
            let initial = task.page(
                after_cursor,
                limit,
                self.source_overflow.load(Ordering::Relaxed),
            );
            if !initial.0.is_empty() || initial.2 {
                (initial, None)
            } else {
                let (sender, receiver) = mpsc::channel(1);
                task.subscribers.push(sender);
                (initial, Some(receiver))
            }
        };
        let Some(mut receiver) = receiver else {
            return Ok(initial);
        };
        let _ = tokio::time::timeout(std::time::Duration::from_millis(25), receiver.recv()).await;
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
        let Some(task) = tasks.get_mut(&task_id) else {
            return Ok((Vec::new(), after_cursor, false));
        };
        Ok(task.page(
            after_cursor,
            limit,
            self.source_overflow.load(Ordering::Relaxed),
        ))
    }
}

impl LiveTaskUpdates {
    fn page(
        &mut self,
        after_cursor: Option<u64>,
        limit: u16,
        source_overflow: u64,
    ) -> (Vec<LiveUpdateEnvelope>, Option<u64>, bool) {
        if source_overflow > self.observed_source_overflow {
            self.observed_source_overflow = source_overflow;
            return (
                Vec::new(),
                self.ring
                    .back()
                    .map(|update| update.cursor)
                    .or(after_cursor),
                true,
            );
        }
        live_update_page(self, after_cursor, limit)
    }
}

fn live_update_page(
    task: &LiveTaskUpdates,
    after_cursor: Option<u64>,
    limit: u16,
) -> (Vec<LiveUpdateEnvelope>, Option<u64>, bool) {
    let oldest = task.ring.front().map(|update| update.cursor);
    let latest = task.ring.back().map(|update| update.cursor);
    let overflowed = match (after_cursor, oldest) {
        (Some(cursor), Some(oldest)) => cursor.saturating_add(1) < oldest,
        (None, Some(oldest)) => oldest > 1,
        _ => false,
    };
    if overflowed {
        return (Vec::new(), latest, true);
    }
    let updates = task
        .ring
        .iter()
        .filter(|update| after_cursor.is_none_or(|cursor| update.cursor > cursor))
        .take(usize::from(limit))
        .cloned()
        .collect::<Vec<_>>();
    let updates = if updates.is_empty()
        && let (Some(after), Some(pending)) = (after_cursor, task.pending_approval.as_ref())
        && after >= pending.cursor
    {
        vec![pending.clone()]
    } else {
        updates
    };
    let cursor = updates.last().map(|update| update.cursor).or(after_cursor);
    (updates, cursor, false)
}

fn map_live_update((task_id, update): (TaskId, TaskEngineUpdate)) -> Option<(TaskId, TaskUpdate)> {
    match update {
        TaskEngineUpdate::AgentMessageChunk(text)
            if text.len() <= 64 * 1024
                && crate::security::SecretFilter
                    .inspect(text.as_bytes())
                    .is_ok() =>
        {
            Some((task_id, TaskUpdate::AssistantDelta(text)))
        }
        TaskEngineUpdate::DiffUpdated(diff)
            if diff.len() <= 64 * 1024
                && crate::security::SecretFilter
                    .inspect(diff.as_bytes())
                    .is_ok() =>
        {
            Some((task_id, TaskUpdate::Diff(diff)))
        }
        _ => None,
    }
}

enum ActorCommand {
    Cancel {
        task_id: TaskId,
        control_id: String,
        reply: oneshot::Sender<Result<(), TaskServiceError>>,
    },
    Steer {
        task_id: TaskId,
        text: String,
        control_id: String,
        reply: oneshot::Sender<Result<(), TaskServiceError>>,
    },
    Resume {
        task_id: TaskId,
        control_id: String,
        reply: oneshot::Sender<Result<(), TaskServiceError>>,
    },
    Configure {
        task_id: TaskId,
        control_id: String,
        model: crate::delegates::ModelId,
        effort: crate::delegates::ReasoningEffort,
        permission_mode: PermissionMode,
        reply: oneshot::Sender<Result<(), TaskServiceError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), TaskServiceError>>,
    },
}

async fn run_task_actor<P: AgentPort + 'static>(
    mut engine: TaskEngine<P, RuntimeStore>,
    initial_tasks: Vec<TaskId>,
    mut commands: mpsc::Receiver<ActorCommand>,
    active_task: Arc<tokio::sync::Mutex<Option<TaskId>>>,
) -> Result<(), TaskServiceError> {
    let mut scheduled = initial_tasks.into_iter().collect::<VecDeque<_>>();
    loop {
        if scheduled.is_empty() {
            scheduled.extend(
                engine
                    .store()
                    .list_resumable_tasks()
                    .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                    .into_iter()
                    .filter(|record| is_schedulable(record.snapshot.status))
                    .map(|record| record.snapshot.task_id),
            );
        }
        if let Some(task_id) = scheduled.pop_front() {
            *active_task.lock().await = Some(task_id);
            engine
                .install_owner_frontend_context(task_id)
                .map_err(map_engine)?;
            let _ = engine.run(task_id).await;
            let _ = engine.take_updates();
            *active_task.lock().await = None;
            continue;
        }
        tokio::select! {
            processed = engine.receive_owner_control_while_idle() => {
                if !processed {
                    return Err(service_error(TaskServiceErrorCode::Stopped));
                }
                let _ = engine.take_updates();
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    let _ = engine.port_mut().shutdown().await;
                    return Ok(());
                };
                match command {
                    ActorCommand::Cancel { task_id, control_id, reply } => {
                        let result = engine
                            .cancel_controlled(task_id, Some(&control_id))
                            .await;
                        let _ = reply.send(map_control_result(result));
                    }
                    ActorCommand::Steer { task_id, text, control_id, reply } => {
                        let result = engine
                            .steer_controlled(task_id, text, Some(&control_id))
                            .await
                            .map_err(map_engine);
                        let _ = reply.send(result);
                    }
                    ActorCommand::Resume { task_id, control_id, reply } => {
                        let result = engine
                            .store()
                            .get_task(task_id)
                            .map_err(|_| service_error(TaskServiceErrorCode::Storage))
                            .and_then(|record| record.ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest)))
                            .and_then(|record| {
                                if record.snapshot.status.is_terminal() {
                                    Err(service_error(TaskServiceErrorCode::InvalidRequest))
                                } else {
                                    engine
                                        .mark_control_requested(task_id, &control_id, TaskControlKind::Resume)
                                        .map_err(map_engine)
                                }
                            });
                        if result.is_ok() {
                            scheduled.push_back(task_id);
                        }
                        let _ = reply.send(result);
                    }
                    ActorCommand::Configure {
                        task_id,
                        control_id,
                        model,
                        effort,
                        permission_mode,
                        reply,
                    } => {
                        let result = engine
                            .configure_controlled(
                                task_id,
                                control_id,
                                model,
                                effort,
                                permission_mode,
                            )
                            .map_err(map_engine);
                        let _ = reply.send(result);
                    }
                    ActorCommand::Shutdown { reply } => {
                        let result = engine
                            .port_mut()
                            .shutdown()
                            .await
                            .map_err(|_| service_error(TaskServiceErrorCode::Engine));
                        let succeeded = result.is_ok();
                        let _ = reply.send(result);
                        if succeeded {
                            return Ok(());
                        }
                    }
                }
                let _ = engine.take_updates();
            }
        }
    }
}

async fn handle_connection(
    reader: LocalReader,
    mut writer: LocalWriter,
    shared: Arc<ServiceShared>,
    stop: CancellationToken,
) -> Result<(), TaskServiceError> {
    let mut reader = BufReader::new(reader);
    let mut ledger = RequestLedger::default();
    loop {
        let Some(line) = read_bounded_line(&mut reader).await? else {
            return Ok(());
        };
        let request = match decode_request_line(&line, &mut ledger) {
            Ok(request) => request,
            Err(error) => {
                let frame = ServiceFrame::Error {
                    request_id: String::new(),
                    code: protocol_code(error.code()).to_owned(),
                    message: "service request rejected".to_owned(),
                };
                writer
                    .write_all(
                        &encode_frame(&frame)
                            .map_err(|_| service_error(TaskServiceErrorCode::Transport))?,
                    )
                    .await
                    .map_err(|_| service_error(TaskServiceErrorCode::Transport))?;
                writer
                    .flush()
                    .await
                    .map_err(|_| service_error(TaskServiceErrorCode::Transport))?;
                return Ok(());
            }
        };
        let shutdown = matches!(request.command, ServiceCommand::Shutdown);
        let request_id = request.request_id.clone();
        let frame = match dispatch_request(&shared, request).await {
            Ok(result) => ServiceFrame::Response {
                request_id,
                result: Box::new(result),
            },
            Err(error) => ServiceFrame::Error {
                request_id,
                code: service_code(error.code()).to_owned(),
                message: "service command rejected".to_owned(),
            },
        };
        writer
            .write_all(
                &encode_frame(&frame)
                    .map_err(|_| service_error(TaskServiceErrorCode::Transport))?,
            )
            .await
            .map_err(|_| service_error(TaskServiceErrorCode::Transport))?;
        writer
            .flush()
            .await
            .map_err(|_| service_error(TaskServiceErrorCode::Transport))?;
        if shutdown && matches!(frame, ServiceFrame::Response { .. }) {
            stop.cancel();
            return Ok(());
        }
    }
}

async fn dispatch_request(
    shared: &ServiceShared,
    request: ServiceRequest,
) -> Result<ServiceResult, TaskServiceError> {
    if !is_mutation(&request.command) {
        return execute_command(shared, &request, false).await;
    }
    let _gate = shared.mutation_gate.lock().await;
    let digest = command_digest(&request.command)
        .map_err(|_| service_error(TaskServiceErrorCode::InvalidRequest))?;
    let receipt = ServiceCommandReceiptInput {
        idempotency_key: request.idempotency_key.clone(),
        command_digest: Sha256Digest::from_bytes(digest),
        command_kind: service_command_kind(&request.command).to_owned(),
        created_at: Utc::now(),
    };
    let claim = lock_store(&shared.read_store)?
        .claim_service_command(receipt.clone())
        .map_err(|_| service_error(TaskServiceErrorCode::InvalidRequest))?;
    if let ServiceCommandReceiptClaim::Replay { result_json } = claim {
        let result = serde_json::from_str(&result_json)
            .map_err(|_| service_error(TaskServiceErrorCode::Storage))?;
        if matches!(request.command, ServiceCommand::Shutdown) {
            shutdown_owner(shared).await?;
        }
        return Ok(result);
    }
    let recovering_pending = claim == ServiceCommandReceiptClaim::Pending;
    let result = execute_command(shared, &request, recovering_pending).await?;
    let result_json =
        serde_json::to_string(&result).map_err(|_| service_error(TaskServiceErrorCode::Storage))?;
    lock_store(&shared.read_store)?
        .complete_service_command(&receipt, &result_json, Utc::now())
        .map_err(|_| service_error(TaskServiceErrorCode::Storage))?;
    Ok(result)
}

async fn execute_command(
    shared: &ServiceShared,
    request: &ServiceRequest,
    recovering_pending: bool,
) -> Result<ServiceResult, TaskServiceError> {
    match &request.command {
        ServiceCommand::Info => Ok(ServiceResult::Info(shared.info.clone())),
        ServiceCommand::Session {
            external_session_id,
        } => {
            let store = lock_store(&shared.read_store)?;
            let binding = store
                .get_frontend_session(external_session_id)
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
            let task_ids = store
                .list_tasks_for_session(binding.session_id, 64)
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                .into_iter()
                .map(|record| record.snapshot.task_id)
                .collect();
            Ok(ServiceResult::Session(ServiceSessionInfo {
                external_session_id: external_session_id.clone(),
                session_id: binding.session_id,
                frontend: binding.frontend,
                workspace: binding.cwd,
                channel_id: binding
                    .channel_id
                    .map(|channel| channel.as_str().to_owned()),
                permission_mode: binding.permission_mode,
                task_ids,
            }))
        }
        ServiceCommand::StartTask(command) => {
            validate_model_selection(&shared.info, &command.model, command.effort)?;
            let (reply, response) = oneshot::channel();
            shared
                .controls
                .send(TaskEngineControl::Enqueue {
                    input: OwnerStartTask {
                        external_session_id: command.external_session_id.clone(),
                        workspace: command.workspace.clone(),
                        request: command.request.clone(),
                        model: command.model.clone(),
                        effort: command.effort,
                        permission_mode: command.permission_mode,
                        trusted_admission: None,
                        idempotency_key: request.idempotency_key.clone(),
                        command_digest: command_digest(&request.command)
                            .map_err(|_| service_error(TaskServiceErrorCode::InvalidRequest))?,
                    },
                    reply,
                })
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
            let snapshot = response
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
                .map_err(map_engine)?;
            Ok(ServiceResult::Accepted {
                task_id: snapshot.task_id,
            })
        }
        ServiceCommand::Status { task_id } => {
            let snapshot = lock_store(&shared.read_store)?
                .get_task(*task_id)
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                .map(|record| record.snapshot)
                .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
            Ok(ServiceResult::Snapshot(snapshot))
        }
        ServiceCommand::List => {
            let tasks = lock_store(&shared.read_store)?
                .list_tasks(64)
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                .into_iter()
                .map(|record| record.snapshot)
                .collect();
            Ok(ServiceResult::TaskList(tasks))
        }
        ServiceCommand::Events {
            task_id,
            after_sequence,
            limit,
        } => {
            let events = lock_store(&shared.read_store)?
                .read_task_event_page(*task_id, *after_sequence, *limit)
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?;
            Ok(ServiceResult::Events(events))
        }
        ServiceCommand::LiveUpdates {
            task_id,
            after_cursor,
            limit,
        } => {
            let (updates, cursor, overflowed) = shared
                .live_updates
                .page(*task_id, *after_cursor, *limit)
                .await?;
            let snapshot = if overflowed {
                Some(
                    lock_store(&shared.read_store)?
                        .get_task(*task_id)
                        .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                        .map(|record| record.snapshot)
                        .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?,
                )
            } else {
                None
            };
            Ok(ServiceResult::LiveUpdates(LiveUpdatePage {
                updates,
                cursor,
                snapshot,
            }))
        }
        ServiceCommand::Cancel { task_id } => {
            mutate_task(shared, *task_id, request, Mutation::Cancel).await?;
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::Steer { task_id, text } => {
            mutate_task(shared, *task_id, request, Mutation::Steer(text.clone())).await?;
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::SteerTrusted {
            task_id,
            external_session_id,
            text,
            workspace,
            frontend,
            actor_id,
            channel_id,
            event_id,
        } => {
            let binding_valid = {
                let store = lock_store(&shared.read_store)?;
                let binding = store
                    .get_frontend_session(external_session_id)
                    .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                    .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
                let task = store
                    .get_task(*task_id)
                    .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                    .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
                binding.frontend == Frontend::Buzz
                    && binding.session_id == task.snapshot.session_id
                    && binding.cwd == *workspace
                    && binding.channel_id.as_ref().map(|channel| channel.as_str())
                        == Some(channel_id.as_str())
            };
            if !binding_valid {
                return Err(service_error(TaskServiceErrorCode::InvalidRequest));
            }
            let (reply, response) = oneshot::channel();
            shared
                .controls
                .send(TaskEngineControl::AdmitTrusted {
                    input: OwnerTrustedMessage {
                        workspace: workspace.clone(),
                        admission: OwnerTrustedAdmission {
                            frontend: *frontend,
                            actor_id: actor_id.clone(),
                            channel_id: channel_id.clone(),
                            event_id: event_id.clone(),
                            recover_existing: recovering_pending,
                        },
                    },
                    reply,
                })
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
            response
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
                .map_err(map_engine)?;
            mutate_task(shared, *task_id, request, Mutation::Steer(text.clone())).await?;
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::Resume { task_id } => {
            mutate_task(shared, *task_id, request, Mutation::Resume).await?;
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::Shutdown => {
            shutdown_owner(shared).await?;
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::StartTrustedTask(command) => {
            validate_model_selection(&shared.info, &command.start.model, command.start.effort)?;
            let (reply, response) = oneshot::channel();
            shared
                .controls
                .send(TaskEngineControl::Enqueue {
                    input: OwnerStartTask {
                        external_session_id: command.start.external_session_id.clone(),
                        workspace: command.start.workspace.clone(),
                        request: command.start.request.clone(),
                        model: command.start.model.clone(),
                        effort: command.start.effort,
                        permission_mode: command.start.permission_mode,
                        trusted_admission: Some(OwnerTrustedAdmission {
                            frontend: command.frontend,
                            actor_id: command.actor_id.clone(),
                            channel_id: command.channel_id.clone(),
                            event_id: command.event_id.clone(),
                            recover_existing: recovering_pending,
                        }),
                        idempotency_key: request.idempotency_key.clone(),
                        command_digest: command_digest(&request.command)
                            .map_err(|_| service_error(TaskServiceErrorCode::InvalidRequest))?,
                    },
                    reply,
                })
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
            let snapshot = response
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
                .map_err(map_engine)?;
            Ok(ServiceResult::Accepted {
                task_id: snapshot.task_id,
            })
        }
        ServiceCommand::ConfigureTrustedSession {
            external_session_id,
            workspace,
            frontend,
            actor_id,
            channel_id,
            event_id,
            permission_mode,
        } => {
            let (reply, response) = oneshot::channel();
            shared
                .controls
                .send(TaskEngineControl::ConfigureOwnerSession {
                    input: OwnerConfigureSession {
                        external_session_id: external_session_id.clone(),
                        workspace: workspace.clone(),
                        permission_mode: *permission_mode,
                        admission: OwnerTrustedAdmission {
                            frontend: *frontend,
                            actor_id: actor_id.clone(),
                            channel_id: channel_id.clone(),
                            event_id: event_id.clone(),
                            recover_existing: recovering_pending,
                        },
                    },
                    reply,
                })
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
            response
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
                .map_err(map_engine)?;
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::ResolveApproval {
            task_id,
            external_session_id,
            workspace,
            frontend,
            actor_id,
            channel_id,
            event_id,
            display_code,
            session_id,
            turn_id,
            decision,
        } => {
            if *frontend == Frontend::Buzz {
                let (reply, response) = oneshot::channel();
                shared
                    .controls
                    .send(TaskEngineControl::AdmitTrusted {
                        input: OwnerTrustedMessage {
                            workspace: workspace.clone(),
                            admission: OwnerTrustedAdmission {
                                frontend: *frontend,
                                actor_id: actor_id.clone(),
                                channel_id: channel_id.clone().ok_or_else(|| {
                                    service_error(TaskServiceErrorCode::InvalidRequest)
                                })?,
                                event_id: event_id.clone().ok_or_else(|| {
                                    service_error(TaskServiceErrorCode::InvalidRequest)
                                })?,
                                recover_existing: recovering_pending,
                            },
                        },
                        reply,
                    })
                    .await
                    .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
                response
                    .await
                    .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
                    .map_err(map_engine)?;
            }
            let binding_valid = {
                let store = lock_store(&shared.read_store)?;
                let binding = store
                    .get_frontend_session(external_session_id)
                    .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                    .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
                let task = store
                    .get_task(*task_id)
                    .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                    .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
                binding.frontend == *frontend
                    && binding.cwd == *workspace
                    && binding.session_id == *session_id
                    && task.snapshot.session_id == *session_id
            };
            if !binding_valid || *shared.active_task.lock().await != Some(*task_id) {
                return Err(service_error(TaskServiceErrorCode::InvalidRequest));
            }
            send_active_control(
                shared,
                TaskEngineControl::Approval {
                    display_code: display_code.clone(),
                    decision: match decision {
                        super::protocol::ServiceApprovalDecision::Approve => EffectDecision::Allow,
                        super::protocol::ServiceApprovalDecision::Deny => EffectDecision::Deny,
                    },
                    session_id: *session_id,
                    turn_id: *turn_id,
                    acknowledgement: next_ack(shared)?,
                },
            )
            .await?;
            shared.live_updates.clear_pending_approval(*task_id);
            Ok(ServiceResult::Applied)
        }
        ServiceCommand::Configure {
            task_id,
            model,
            effort,
            permission_mode,
        } => {
            validate_model_selection(&shared.info, model, *effort)?;
            mutate_task(
                shared,
                *task_id,
                request,
                Mutation::Configure {
                    model: model.clone(),
                    effort: *effort,
                    permission_mode: *permission_mode,
                },
            )
            .await?;
            Ok(ServiceResult::Applied)
        }
    }
}

fn service_info(
    models: Vec<crate::runtime::agent_port::AgentModel>,
) -> Result<ServiceInfo, TaskServiceError> {
    if models.len() > 128 {
        return Err(service_error(TaskServiceErrorCode::Engine));
    }
    let mut identifiers = std::collections::BTreeSet::new();
    let models = models
        .into_iter()
        .map(|model| {
            if !identifiers.insert(model.id.as_str().to_owned())
                || model.display_name.is_empty()
                || model.display_name.len() > 256
                || model.display_name.chars().any(char::is_control)
                || model.supported_efforts.is_empty()
                || model.supported_efforts.len() > 6
                || model
                    .supported_efforts
                    .iter()
                    .enumerate()
                    .any(|(index, effort)| model.supported_efforts[..index].contains(effort))
                || !model.supported_efforts.contains(&model.default_effort)
            {
                return Err(service_error(TaskServiceErrorCode::Engine));
            }
            Ok(ServiceModel {
                id: model.id,
                display_name: model.display_name,
                supported_efforts: model.supported_efforts,
                default_effort: model.default_effort,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let default_model = models.first().map(|model| model.id.clone());
    let default_effort = models.first().map(|model| model.default_effort);
    Ok(ServiceInfo {
        protocol_version: super::protocol::SERVICE_PROTOCOL_VERSION,
        models,
        default_model,
        default_effort,
        capabilities: ServiceCapabilities {
            durable_events: true,
            reconnect: true,
            trusted_buzz_admission: true,
            configure_active_task: true,
        },
    })
}

enum Mutation {
    Cancel,
    Steer(String),
    Resume,
    Configure {
        model: crate::delegates::ModelId,
        effort: crate::delegates::ReasoningEffort,
        permission_mode: PermissionMode,
    },
}

const fn service_command_kind(command: &ServiceCommand) -> &'static str {
    match command {
        ServiceCommand::StartTask(_) => "start_task",
        ServiceCommand::StartTrustedTask(_) => "start_trusted_task",
        ServiceCommand::ConfigureTrustedSession { .. } => "configure_trusted_session",
        ServiceCommand::ResolveApproval { .. } => "resolve_approval",
        ServiceCommand::Resume { .. } => "resume",
        ServiceCommand::Steer { .. } => "steer",
        ServiceCommand::SteerTrusted { .. } => "steer_trusted",
        ServiceCommand::Cancel { .. } => "cancel",
        ServiceCommand::Configure { .. } => "configure",
        ServiceCommand::Shutdown => "shutdown",
        ServiceCommand::Info
        | ServiceCommand::Session { .. }
        | ServiceCommand::Status { .. }
        | ServiceCommand::List
        | ServiceCommand::Events { .. }
        | ServiceCommand::LiveUpdates { .. } => "read",
    }
}

async fn mutate_task(
    shared: &ServiceShared,
    task_id: TaskId,
    request: &ServiceRequest,
    mutation: Mutation,
) -> Result<(), TaskServiceError> {
    let method = match &mutation {
        Mutation::Cancel => "cancel",
        Mutation::Steer(_) => "steer",
        Mutation::Resume => "resume",
        Mutation::Configure { .. } => "configure",
    };
    let control_id = service_control_id(task_id, &request.idempotency_key, method);
    let active = *shared.active_task.lock().await;
    if active == Some(task_id) {
        let record = lock_store(&shared.read_store)?
            .get_task(task_id)
            .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
            .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
        return match mutation {
            Mutation::Cancel => {
                send_active_control(
                    shared,
                    TaskEngineControl::Cancel {
                        task_id,
                        control_id: Some(control_id.clone()),
                        session_id: record.snapshot.session_id,
                        turn_id: TurnId::new(),
                        acknowledgement: next_ack(shared)?,
                    },
                )
                .await
            }
            Mutation::Steer(text) => {
                send_active_control(
                    shared,
                    TaskEngineControl::Steer {
                        task_id,
                        text,
                        control_id: Some(control_id.clone()),
                        session_id: record.snapshot.session_id,
                        turn_id: TurnId::new(),
                        acknowledgement: next_ack(shared)?,
                    },
                )
                .await
            }
            Mutation::Resume => Ok(()),
            Mutation::Configure {
                model,
                effort,
                permission_mode,
            } => {
                send_active_control(
                    shared,
                    TaskEngineControl::Configure {
                        task_id,
                        control_id: control_id.clone(),
                        model,
                        effort,
                        permission_mode,
                        acknowledgement: next_ack(shared)?,
                    },
                )
                .await
            }
        };
    }
    if active.is_some() {
        return Err(service_error(TaskServiceErrorCode::Busy));
    }
    let (reply, response) = oneshot::channel();
    let command = match mutation {
        Mutation::Cancel => ActorCommand::Cancel {
            task_id,
            control_id,
            reply,
        },
        Mutation::Steer(text) => ActorCommand::Steer {
            task_id,
            text,
            control_id,
            reply,
        },
        Mutation::Resume => ActorCommand::Resume {
            task_id,
            control_id,
            reply,
        },
        Mutation::Configure {
            model,
            effort,
            permission_mode,
        } => ActorCommand::Configure {
            task_id,
            control_id,
            model,
            effort,
            permission_mode,
            reply,
        },
    };
    shared
        .actor_sender
        .send(command)
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    response
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
}

fn validate_model_selection(
    info: &ServiceInfo,
    model: &crate::delegates::ModelId,
    effort: crate::delegates::ReasoningEffort,
) -> Result<(), TaskServiceError> {
    if info.models.is_empty()
        || !info.models.iter().any(|candidate| {
            candidate.id == *model && candidate.supported_efforts.contains(&effort)
        })
    {
        return Err(service_error(TaskServiceErrorCode::InvalidRequest));
    }
    Ok(())
}

async fn send_active_control(
    shared: &ServiceShared,
    control: TaskEngineControl,
) -> Result<(), TaskServiceError> {
    let acknowledgement = match &control {
        TaskEngineControl::Steer {
            acknowledgement, ..
        }
        | TaskEngineControl::Cancel {
            acknowledgement, ..
        }
        | TaskEngineControl::Configure {
            acknowledgement, ..
        }
        | TaskEngineControl::Approval {
            acknowledgement, ..
        } => *acknowledgement,
        TaskEngineControl::Enqueue { .. }
        | TaskEngineControl::AdmitTrusted { .. }
        | TaskEngineControl::ConfigureOwnerSession { .. } => {
            return Err(service_error(TaskServiceErrorCode::InvalidRequest));
        }
    };
    shared
        .controls
        .send(control)
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    let mut receiver = shared.acknowledgements.lock().await;
    loop {
        let (received, result) = receiver
            .recv()
            .await
            .ok_or_else(|| service_error(TaskServiceErrorCode::Stopped))?;
        if received == acknowledgement {
            return map_control_result(result);
        }
    }
}

async fn shutdown_owner(shared: &ServiceShared) -> Result<(), TaskServiceError> {
    let active_task = *shared.active_task.lock().await;
    if let Some(task_id) = active_task {
        let request = ServiceRequest {
            protocol_version: 1,
            request_id: "service-shutdown".to_owned(),
            idempotency_key: format!("service-shutdown-{task_id}"),
            command: ServiceCommand::Cancel { task_id },
        };
        mutate_task(shared, task_id, &request, Mutation::Cancel).await?;
    }
    let (reply, response) = oneshot::channel();
    shared
        .actor_sender
        .send(ActorCommand::Shutdown { reply })
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    response
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
}

async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, TaskServiceError> {
    let mut line = Vec::new();
    let read = reader
        .take((MAX_SERVICE_FRAME_BYTES + 2) as u64)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Transport))?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() > MAX_SERVICE_FRAME_BYTES + 1 || line.last() != Some(&b'\n') {
        return Err(service_error(TaskServiceErrorCode::InvalidRequest));
    }
    Ok(Some(line))
}

fn lock_store(store: &Mutex<Store>) -> Result<std::sync::MutexGuard<'_, Store>, TaskServiceError> {
    store
        .lock()
        .map_err(|_| service_error(TaskServiceErrorCode::Storage))
}

fn next_ack(shared: &ServiceShared) -> Result<u64, TaskServiceError> {
    shared
        .next_acknowledgement
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))
}

const fn is_schedulable(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Queued | TaskStatus::Active | TaskStatus::Checkpointing | TaskStatus::Paused
    )
}

fn map_control_result(result: Result<(), TaskEngineError>) -> Result<(), TaskServiceError> {
    match result {
        Err(error) if error.code() == TaskEngineErrorCode::Cancelled => Ok(()),
        Err(error) => Err(map_engine(error)),
        Ok(()) => Ok(()),
    }
}

fn service_control_id(task_id: TaskId, idempotency_key: &str, method: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("carl-service-v1:{task_id}:{method}:{idempotency_key}").as_bytes())
    )
}

fn map_engine(error: TaskEngineError) -> TaskServiceError {
    match error.code() {
        TaskEngineErrorCode::InvalidTask => service_error(TaskServiceErrorCode::InvalidRequest),
        TaskEngineErrorCode::Cancelled => service_error(TaskServiceErrorCode::Engine),
        TaskEngineErrorCode::Storage => service_error(TaskServiceErrorCode::Storage),
        TaskEngineErrorCode::Provider
        | TaskEngineErrorCode::Context
        | TaskEngineErrorCode::Verification
        | TaskEngineErrorCode::Blocked => service_error(TaskServiceErrorCode::Engine),
    }
}

const fn service_error(code: TaskServiceErrorCode) -> TaskServiceError {
    TaskServiceError { code }
}

const fn protocol_code(code: ProtocolErrorCode) -> &'static str {
    match code {
        ProtocolErrorCode::InvalidFrame => "invalid_frame",
        ProtocolErrorCode::FrameTooLarge => "frame_too_large",
        ProtocolErrorCode::UnsupportedVersion => "unsupported_version",
        ProtocolErrorCode::InvalidIdentifier => "invalid_identifier",
        ProtocolErrorCode::InvalidRequest => "invalid_request",
        ProtocolErrorCode::InvalidEventLimit => "invalid_event_limit",
        ProtocolErrorCode::DuplicateRequestId => "duplicate_request_id",
        ProtocolErrorCode::IdempotencyConflict => "idempotency_conflict",
        ProtocolErrorCode::LedgerFull => "ledger_full",
    }
}

const fn service_code(code: TaskServiceErrorCode) -> &'static str {
    match code {
        TaskServiceErrorCode::Endpoint => "endpoint",
        TaskServiceErrorCode::Storage => "storage",
        TaskServiceErrorCode::Engine => "engine",
        TaskServiceErrorCode::Transport => "transport",
        TaskServiceErrorCode::InvalidRequest => "invalid_request",
        TaskServiceErrorCode::Busy => "busy",
        TaskServiceErrorCode::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::SessionId;
    use crate::runtime::task::OperationId;

    #[test]
    fn source_queue_loss_forces_one_snapshot_fallback() {
        let mut updates = LiveTaskUpdates::default();
        updates.ring.push_back(LiveUpdateEnvelope {
            cursor: 1,
            update: TaskUpdate::AssistantDelta("visible".to_owned()),
        });

        let (page, cursor, overflowed) = updates.page(None, 128, 0);
        assert_eq!(page.len(), 1);
        assert_eq!(cursor, Some(1));
        assert!(!overflowed);

        let (page, cursor, overflowed) = updates.page(Some(1), 128, 1);
        assert!(page.is_empty());
        assert_eq!(cursor, Some(1));
        assert!(overflowed);

        let (_, _, overflowed) = updates.page(Some(1), 128, 1);
        assert!(
            !overflowed,
            "one source loss must not loop snapshot fallback"
        );
    }

    #[tokio::test]
    async fn pending_approval_replays_at_the_live_cursor_until_cleared() {
        let task_id = TaskId::new();
        let hub = LiveUpdateHub::new(Arc::new(AtomicU64::new(0)));
        hub.publish(
            task_id,
            TaskUpdate::ApprovalRequired {
                task_id,
                operation_id: OperationId::new(),
                display_code: "123456".to_owned(),
                summary: "run a command".to_owned(),
                request_id: "approval-request".to_owned(),
                session_id: SessionId::new(),
                turn_id: TurnId::new(),
                external_session_id: "external-session".to_owned(),
            },
        );

        let (replayed, cursor, overflowed) = hub.page(task_id, Some(1), 128).await.unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(cursor, Some(1));
        assert!(!overflowed);
        assert!(matches!(
            replayed[0].update,
            TaskUpdate::ApprovalRequired { .. }
        ));

        hub.clear_pending_approval(task_id);
        let (cleared, cursor, overflowed) = hub.page(task_id, Some(1), 128).await.unwrap();
        assert!(cleared.is_empty());
        assert_eq!(cursor, Some(1));
        assert!(!overflowed);
    }
}
