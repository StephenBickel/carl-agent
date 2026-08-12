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
    CheckpointId, OwnerConfigureSession, OwnerStartTask, OwnerTrustedAdmission,
    OwnerTrustedMessage, TaskControlKind, TaskEngine, TaskEngineAcknowledgement, TaskEngineControl,
    TaskEngineError, TaskEngineErrorCode, TaskEngineUpdate, TaskId, TaskSnapshot, TaskStatus,
};
use crate::sidecar::{DataRootLock, DataRootLockErrorCode};
use crate::storage::{RuntimeStore, ServiceCommandReceiptClaim, ServiceCommandReceiptInput, Store};

use super::protocol::{
    LiveUpdateEnvelope, LiveUpdatePage, MAX_SERVICE_FRAME_BYTES, MaintenancePhase,
    ProtocolErrorCode, RequestLedger, ServiceCapabilities, ServiceCommand, ServiceFrame,
    ServiceInfo, ServiceMaintenanceStatus, ServiceModel, ServiceRequest, ServiceResult,
    ServiceSessionInfo, TaskUpdate, command_digest, decode_request_line, encode_frame, is_mutation,
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

#[cfg(any(windows, test))]
pub(crate) const WINDOWS_PIPE_ACCESS: u32 = 0xC000_0000;

#[cfg(windows)]
pub(crate) fn create_owner_pipe(
    pipe_name: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, EndpointError> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let descriptor = crate::sidecar::windows_security::owner_only_security_descriptor_for_access(
        WINDOWS_PIPE_ACCESS,
    )
    .map_err(|()| endpoint_error(EndpointErrorCode::Unavailable))?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))?,
        lpSecurityDescriptor: descriptor.as_ptr().cast_mut().cast(),
        bInheritHandle: 0,
    };
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `attributes` and its security descriptor are valid during pipe
    // creation. CreateNamedPipe copies the descriptor before returning.
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&raw mut attributes).cast::<core::ffi::c_void>(),
        )
    }
    .map_err(|_| endpoint_error(EndpointErrorCode::Unavailable))
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
    actor_state: Arc<TaskActorState>,
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
            actor_state: Arc::new(TaskActorState::default()),
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
            actor_state,
            info,
        } = self;
        let (actor_sender, actor_receiver) = mpsc::channel(SERVICE_COMMAND_CAPACITY);
        let actor_lifecycle = Arc::clone(&actor_state);
        let mut actor_task = AbortOnDrop::new(tokio::spawn(run_task_actor(
            engine,
            initial_tasks,
            actor_receiver,
            actor_lifecycle,
        )));
        let shared = Arc::new(ServiceShared {
            read_store,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates: Arc::clone(&live_updates),
            next_acknowledgement,
            actor_state,
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
                    shutdown_owner_after_mutations(&shared).await?;
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

struct TaskActorState {
    owner: tokio::sync::Mutex<TaskActorOwner>,
    changed: tokio::sync::Notify,
}

struct TaskActorOwner {
    active_task: Option<TaskId>,
    phase: MaintenancePhase,
    maintenance_task: Option<TaskId>,
    maintenance_checkpoint: Option<CheckpointId>,
    maintenance_idempotency_key: Option<String>,
    emergency_requested: bool,
    emergency_target: Option<TaskId>,
}

impl Default for TaskActorState {
    fn default() -> Self {
        Self {
            owner: tokio::sync::Mutex::new(TaskActorOwner {
                active_task: None,
                phase: MaintenancePhase::Running,
                maintenance_task: None,
                maintenance_checkpoint: None,
                maintenance_idempotency_key: None,
                emergency_requested: false,
                emergency_target: None,
            }),
            changed: tokio::sync::Notify::new(),
        }
    }
}

impl TaskActorState {
    async fn claim_start(&self, task_id: TaskId) -> bool {
        let mut owner = self.owner.lock().await;
        if owner.phase != MaintenancePhase::Running || owner.emergency_requested {
            return false;
        }
        owner.active_task = Some(task_id);
        true
    }

    async fn publish_shutdown(&self) -> Option<TaskId> {
        let mut owner = self.owner.lock().await;
        owner.emergency_requested = true;
        if owner.emergency_target.is_none() {
            owner.emergency_target = owner.active_task;
        }
        let target = owner.emergency_target;
        drop(owner);
        target
    }

    async fn begin_maintenance(&self, idempotency_key: Option<&str>) -> ServiceMaintenanceStatus {
        let mut owner = self.owner.lock().await;
        if owner.phase == MaintenancePhase::Running {
            owner.maintenance_idempotency_key = idempotency_key.map(str::to_owned);
            match owner.active_task {
                Some(task_id) => {
                    owner.phase = MaintenancePhase::Draining;
                    owner.maintenance_task = Some(task_id);
                    owner.maintenance_checkpoint = None;
                }
                None => owner.phase = MaintenancePhase::Ready,
            }
        }
        let status = maintenance_status(&owner);
        drop(owner);
        self.changed.notify_waiters();
        status
    }

    async fn clear_active(&self, task_id: TaskId, snapshot: &TaskSnapshot) -> bool {
        let mut owner = self.owner.lock().await;
        if owner.active_task == Some(task_id) {
            owner.active_task = None;
        }
        if owner.phase == MaintenancePhase::Draining && owner.maintenance_task == Some(task_id) {
            owner.phase = MaintenancePhase::Ready;
            if snapshot.latest_checkpoint.is_some() {
                owner.maintenance_checkpoint = snapshot.latest_checkpoint;
            } else {
                owner.maintenance_task = None;
            }
            drop(owner);
            self.changed.notify_waiters();
            return true;
        }
        drop(owner);
        false
    }

    async fn status(&self) -> ServiceMaintenanceStatus {
        maintenance_status(&*self.owner.lock().await)
    }

    async fn wait_ready(&self) -> ServiceMaintenanceStatus {
        loop {
            let notified = self.changed.notified();
            let status = self.status().await;
            if status.phase == MaintenancePhase::Ready {
                return status;
            }
            notified.await;
        }
    }

    async fn active_task(&self) -> Option<TaskId> {
        self.owner.lock().await.active_task
    }

    async fn starts_stopped(&self) -> bool {
        let owner = self.owner.lock().await;
        owner.phase != MaintenancePhase::Running || owner.emergency_requested
    }

    async fn rejects_mutations(&self) -> bool {
        let owner = self.owner.lock().await;
        owner.phase != MaintenancePhase::Running || owner.emergency_requested
    }

    async fn allows_prepare(&self, idempotency_key: &str) -> bool {
        let owner = self.owner.lock().await;
        owner.phase == MaintenancePhase::Running
            || owner.maintenance_idempotency_key.as_deref() == Some(idempotency_key)
    }
}

fn maintenance_status(owner: &TaskActorOwner) -> ServiceMaintenanceStatus {
    ServiceMaintenanceStatus {
        schema_version: 1,
        phase: owner.phase,
        task_id: match owner.phase {
            MaintenancePhase::Running => owner.active_task,
            MaintenancePhase::Draining | MaintenancePhase::Ready => owner.maintenance_task,
        },
        checkpoint_id: owner.maintenance_checkpoint,
    }
}

struct ServiceShared {
    read_store: Arc<Mutex<Store>>,
    controls: mpsc::Sender<TaskEngineControl>,
    acknowledgements: Arc<tokio::sync::Mutex<mpsc::Receiver<TaskEngineAcknowledgement>>>,
    mutation_gate: Arc<tokio::sync::Mutex<()>>,
    live_updates: Arc<LiveUpdateHub>,
    next_acknowledgement: Arc<AtomicU64>,
    actor_state: Arc<TaskActorState>,
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
    next_subscriber: u64,
    subscribers: HashMap<u64, mpsc::Sender<LiveUpdateEnvelope>>,
    observed_source_overflow: u64,
    pending_approval: Option<LiveUpdateEnvelope>,
}

impl Default for LiveTaskUpdates {
    fn default() -> Self {
        Self {
            next_cursor: 1,
            ring: VecDeque::new(),
            next_subscriber: 1,
            subscribers: HashMap::new(),
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
            .retain(|_, subscriber| subscriber.try_send(envelope.clone()).is_ok());
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
                let subscriber = task.next_subscriber;
                task.next_subscriber = task
                    .next_subscriber
                    .checked_add(1)
                    .ok_or_else(|| service_error(TaskServiceErrorCode::Stopped))?;
                task.subscribers.insert(subscriber, sender);
                (initial, Some((subscriber, receiver)))
            }
        };
        let Some((subscriber, mut receiver)) = receiver else {
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
        task.subscribers.remove(&subscriber);
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

fn live_after_cursor(
    requested_generation: &str,
    current_generation: &str,
    after_cursor: Option<u64>,
) -> Option<u64> {
    (requested_generation == current_generation)
        .then_some(after_cursor)
        .flatten()
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
    ShutdownProvider {
        reply: oneshot::Sender<Result<(), TaskServiceError>>,
    },
}

async fn run_task_actor<P: AgentPort + 'static>(
    mut engine: TaskEngine<P, RuntimeStore>,
    initial_tasks: Vec<TaskId>,
    mut commands: mpsc::Receiver<ActorCommand>,
    actor_state: Arc<TaskActorState>,
) -> Result<(), TaskServiceError> {
    let mut scheduled = initial_tasks.into_iter().collect::<VecDeque<_>>();
    let mut provider_shutdown = false;
    loop {
        // Owner commands, especially shutdown, preempt every future refill/start.
        if let Ok(command) = commands.try_recv() {
            handle_actor_command(
                &mut engine,
                &mut scheduled,
                &mut provider_shutdown,
                &actor_state,
                command,
            )
            .await;
            continue;
        }
        let starts_stopped = actor_state.starts_stopped().await;
        if scheduled.is_empty() && !provider_shutdown && !starts_stopped {
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
        if !provider_shutdown
            && !starts_stopped
            && let Some(task_id) = scheduled.front().copied()
            && actor_state.claim_start(task_id).await
        {
            let claimed = scheduled
                .pop_front()
                .expect("the actor start claim preserves the scheduled front");
            debug_assert_eq!(claimed, task_id);
            engine
                .install_owner_frontend_context(task_id)
                .map_err(map_engine)?;
            let result = engine.run(task_id).await;
            let _ = engine.take_updates();
            let snapshot = result.ok().or_else(|| {
                engine
                    .store()
                    .get_task(task_id)
                    .ok()
                    .flatten()
                    .map(|record| record.snapshot)
            });
            if let Some(snapshot) = snapshot
                && actor_state.clear_active(task_id, &snapshot).await
            {
                if engine.port_mut().shutdown().await.is_ok() {
                    provider_shutdown = true;
                    scheduled.clear();
                } else {
                    return Err(service_error(TaskServiceErrorCode::Engine));
                }
            }
            continue;
        }
        tokio::select! {
            processed = engine.receive_owner_control_while_idle() => {
                if !processed {
                    return if provider_shutdown {
                        Ok(())
                    } else {
                        Err(service_error(TaskServiceErrorCode::Stopped))
                    };
                }
                let _ = engine.take_updates();
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    if !provider_shutdown {
                        let _ = engine.port_mut().shutdown().await;
                    }
                    return Ok(());
                };
                handle_actor_command(
                    &mut engine,
                    &mut scheduled,
                    &mut provider_shutdown,
                    &actor_state,
                    command,
                )
                .await;
            }
        }
    }
}

async fn handle_actor_command<P: AgentPort>(
    engine: &mut TaskEngine<P, RuntimeStore>,
    scheduled: &mut VecDeque<TaskId>,
    provider_shutdown: &mut bool,
    actor_state: &TaskActorState,
    command: ActorCommand,
) {
    match command {
        ActorCommand::Cancel {
            task_id,
            control_id,
            reply,
        } => {
            let result = engine.cancel_controlled(task_id, Some(&control_id)).await;
            let _ = reply.send(map_control_result(result));
        }
        ActorCommand::Steer {
            task_id,
            text,
            control_id,
            reply,
        } => {
            let result = engine
                .steer_controlled(task_id, text, Some(&control_id))
                .await
                .map_err(map_engine);
            let _ = reply.send(result);
        }
        ActorCommand::Resume {
            task_id,
            control_id,
            reply,
        } => {
            let mut result = if *provider_shutdown || actor_state.starts_stopped().await {
                Err(service_error(TaskServiceErrorCode::Stopped))
            } else {
                engine
                    .store()
                    .get_task(task_id)
                    .map_err(|_| service_error(TaskServiceErrorCode::Storage))
                    .and_then(|record| {
                        record.ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))
                    })
                    .and_then(|record| {
                        if record.snapshot.status.is_terminal() {
                            Err(service_error(TaskServiceErrorCode::InvalidRequest))
                        } else {
                            engine
                                .mark_control_requested(
                                    task_id,
                                    &control_id,
                                    TaskControlKind::Resume,
                                )
                                .map_err(map_engine)
                        }
                    })
            };
            if result.is_ok() {
                result =
                    enqueue_resumed_task(actor_state, *provider_shutdown, scheduled, task_id).await;
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
                .configure_controlled(task_id, control_id, model, effort, permission_mode)
                .map_err(map_engine);
            let _ = reply.send(result);
        }
        ActorCommand::ShutdownProvider { reply } => {
            let result = if *provider_shutdown {
                Ok(())
            } else {
                engine
                    .port_mut()
                    .shutdown()
                    .await
                    .map_err(|_| service_error(TaskServiceErrorCode::Engine))
            };
            if result.is_ok() {
                *provider_shutdown = true;
                scheduled.clear();
            }
            let _ = reply.send(result);
        }
    }
    let _ = engine.take_updates();
}

async fn enqueue_resumed_task(
    actor_state: &TaskActorState,
    provider_shutdown: bool,
    scheduled: &mut VecDeque<TaskId>,
    task_id: TaskId,
) -> Result<(), TaskServiceError> {
    if provider_shutdown || actor_state.starts_stopped().await {
        return Err(service_error(TaskServiceErrorCode::Stopped));
    }
    scheduled.push_back(task_id);
    Ok(())
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
    if matches!(request.command, ServiceCommand::PrepareMaintenance)
        && !shared
            .actor_state
            .allows_prepare(&request.idempotency_key)
            .await
    {
        return Err(service_error(TaskServiceErrorCode::Stopped));
    }
    if !matches!(
        request.command,
        ServiceCommand::PrepareMaintenance | ServiceCommand::Shutdown
    ) && shared.actor_state.rejects_mutations().await
    {
        return Err(service_error(TaskServiceErrorCode::Stopped));
    }
    let digest = command_digest(&request.command)
        .map_err(|_| service_error(TaskServiceErrorCode::InvalidRequest))?;
    let receipt = ServiceCommandReceiptInput {
        idempotency_key: request.idempotency_key.clone(),
        command_digest: Sha256Digest::from_bytes(digest),
        command_kind: service_command_kind(&request.command).to_owned(),
        created_at: Utc::now(),
    };
    let claim = claim_service_command(shared, receipt.clone()).await?;
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
    complete_service_command(shared, receipt, result_json).await?;
    Ok(result)
}

async fn claim_service_command(
    shared: &ServiceShared,
    input: ServiceCommandReceiptInput,
) -> Result<ServiceCommandReceiptClaim, TaskServiceError> {
    let (reply, response) = oneshot::channel();
    shared
        .controls
        .send(TaskEngineControl::ClaimServiceCommand { input, reply })
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    response
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
        .map_err(|_| service_error(TaskServiceErrorCode::InvalidRequest))
}

async fn complete_service_command(
    shared: &ServiceShared,
    input: ServiceCommandReceiptInput,
    result_json: String,
) -> Result<(), TaskServiceError> {
    let (reply, response) = oneshot::channel();
    shared
        .controls
        .send(TaskEngineControl::CompleteServiceCommand {
            input,
            result_json,
            completed_at: Utc::now(),
            reply,
        })
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    response
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
        .map(|_| ())
        .map_err(map_engine)
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
                        budget: command.budget,
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
        ServiceCommand::Metrics { task_id } => {
            let metrics = lock_store(&shared.read_store)?
                .task_metrics(*task_id)
                .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
                .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
            Ok(ServiceResult::Metrics(metrics))
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
            live_generation,
            after_cursor,
            limit,
        } => {
            let after_cursor =
                live_after_cursor(live_generation, &shared.info.live_generation, *after_cursor);
            let (updates, cursor, overflowed) = shared
                .live_updates
                .page(*task_id, after_cursor, *limit)
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
                live_generation: shared.info.live_generation.clone(),
                updates,
                cursor,
                snapshot,
            }))
        }
        ServiceCommand::MaintenanceStatus => Ok(ServiceResult::Maintenance(
            shared.actor_state.status().await,
        )),
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
        ServiceCommand::PrepareMaintenance => Ok(ServiceResult::Maintenance(
            prepare_maintenance(shared, Some(&request.idempotency_key)).await?,
        )),
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
                        budget: command.start.budget,
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
            if !binding_valid || shared.actor_state.active_task().await != Some(*task_id) {
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
        live_generation: uuid::Uuid::new_v4().to_string(),
        models,
        default_model,
        default_effort,
        capabilities: ServiceCapabilities {
            durable_events: true,
            reconnect: true,
            trusted_buzz_admission: true,
            configure_active_task: true,
            explicit_task_budgets: true,
            sanitized_task_metrics: true,
            recoverable_maintenance: true,
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
        ServiceCommand::PrepareMaintenance => "prepare_maintenance",
        ServiceCommand::Shutdown => "shutdown",
        ServiceCommand::Info
        | ServiceCommand::Session { .. }
        | ServiceCommand::Status { .. }
        | ServiceCommand::Metrics { .. }
        | ServiceCommand::List
        | ServiceCommand::Events { .. }
        | ServiceCommand::LiveUpdates { .. }
        | ServiceCommand::MaintenanceStatus => "read",
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
    let active = shared.actor_state.active_task().await;
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
        }
        | TaskEngineControl::Quiesce {
            acknowledgement, ..
        } => *acknowledgement,
        TaskEngineControl::ClaimServiceCommand { .. }
        | TaskEngineControl::CompleteServiceCommand { .. }
        | TaskEngineControl::Enqueue { .. }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownCancelRoute {
    Quiesced,
    Active,
    Idle,
}

fn classify_shutdown_cancel(
    status: TaskStatus,
    active_task: Option<TaskId>,
    task_id: TaskId,
) -> Result<ShutdownCancelRoute, TaskServiceError> {
    if status.is_terminal() {
        return Ok(ShutdownCancelRoute::Quiesced);
    }
    match active_task {
        Some(active_task) if active_task == task_id => Ok(ShutdownCancelRoute::Active),
        Some(_) => Err(service_error(TaskServiceErrorCode::Busy)),
        None => Ok(ShutdownCancelRoute::Idle),
    }
}

async fn shutdown_cancel_state(
    shared: &ServiceShared,
    task_id: TaskId,
) -> Result<(ShutdownCancelRoute, crate::events::SessionId), TaskServiceError> {
    let active_task = shared.actor_state.active_task().await;
    let record = lock_store(&shared.read_store)?
        .get_task(task_id)
        .map_err(|_| service_error(TaskServiceErrorCode::Storage))?
        .ok_or_else(|| service_error(TaskServiceErrorCode::InvalidRequest))?;
    Ok((
        classify_shutdown_cancel(record.snapshot.status, active_task, task_id)?,
        record.snapshot.session_id,
    ))
}

async fn send_idle_shutdown_cancel(
    shared: &ServiceShared,
    task_id: TaskId,
    control_id: String,
) -> Result<(), TaskServiceError> {
    let (reply, response) = oneshot::channel();
    shared
        .actor_sender
        .send(ActorCommand::Cancel {
            task_id,
            control_id,
            reply,
        })
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    response
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
}

async fn quiesce_shutdown_task(
    shared: &ServiceShared,
    task_id: TaskId,
) -> Result<(), TaskServiceError> {
    let control_id = service_control_id(task_id, &format!("service-shutdown-{task_id}"), "cancel");
    let (mut route, mut session_id) = shutdown_cancel_state(shared, task_id).await?;
    loop {
        match route {
            ShutdownCancelRoute::Quiesced => return Ok(()),
            ShutdownCancelRoute::Active => {
                let result = send_active_control(
                    shared,
                    TaskEngineControl::Cancel {
                        task_id,
                        control_id: Some(control_id.clone()),
                        session_id,
                        turn_id: TurnId::new(),
                        acknowledgement: next_ack(shared)?,
                    },
                )
                .await;
                tokio::task::yield_now().await;
                (route, session_id) = shutdown_cancel_state(shared, task_id).await?;
                match route {
                    ShutdownCancelRoute::Quiesced | ShutdownCancelRoute::Idle => continue,
                    ShutdownCancelRoute::Active => {
                        return result
                            .and_then(|()| Err(service_error(TaskServiceErrorCode::Engine)));
                    }
                }
            }
            ShutdownCancelRoute::Idle => {
                let result = send_idle_shutdown_cancel(shared, task_id, control_id.clone()).await;
                let (after_cancel, _) = shutdown_cancel_state(shared, task_id).await?;
                if after_cancel == ShutdownCancelRoute::Quiesced {
                    return Ok(());
                }
                return result.and_then(|()| Err(service_error(TaskServiceErrorCode::Engine)));
            }
        }
    }
}

async fn shutdown_owner(shared: &ServiceShared) -> Result<(), TaskServiceError> {
    // Publishing under the task-claim mutex linearizes shutdown against every
    // provider start: shutdown either prevents the claim or observes what won.
    let active_task = shared.actor_state.publish_shutdown().await;
    if let Some(task_id) = active_task {
        quiesce_shutdown_task(shared, task_id).await?;
    }
    let (reply, response) = oneshot::channel();
    shared
        .actor_sender
        .send(ActorCommand::ShutdownProvider { reply })
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
    response
        .await
        .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?
}

async fn prepare_maintenance(
    shared: &ServiceShared,
    idempotency_key: Option<&str>,
) -> Result<ServiceMaintenanceStatus, TaskServiceError> {
    let status = shared.actor_state.begin_maintenance(idempotency_key).await;
    match status.phase {
        MaintenancePhase::Running => unreachable!("prepare transitions out of running"),
        MaintenancePhase::Draining => {
            let task_id = status
                .task_id
                .ok_or_else(|| service_error(TaskServiceErrorCode::Engine))?;
            send_active_control(
                shared,
                TaskEngineControl::Quiesce {
                    task_id,
                    acknowledgement: next_ack(shared)?,
                },
            )
            .await?;
        }
        MaintenancePhase::Ready => {
            let (reply, response) = oneshot::channel();
            shared
                .actor_sender
                .send(ActorCommand::ShutdownProvider { reply })
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))?;
            response
                .await
                .map_err(|_| service_error(TaskServiceErrorCode::Stopped))??;
        }
    }
    Ok(status)
}

async fn shutdown_owner_after_mutations(shared: &ServiceShared) -> Result<(), TaskServiceError> {
    let _gate = shared.mutation_gate.lock().await;
    let _ = prepare_maintenance(shared, None).await?;
    let _ = shared.actor_state.wait_ready().await;
    Ok(())
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
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use crate::delegates::{ModelId, ReasoningEffort};
    use crate::events::SessionId;
    #[cfg(unix)]
    use crate::runtime::agent_port::{
        AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
        AgentEvent, AgentFuture, AgentItem, AgentModel, AgentProcess, AgentRequestId,
        ResumeAgentContext, StartAgentContext, StartAgentEpoch,
    };
    use crate::runtime::task::{OperationId, OperationStatus};
    #[cfg(unix)]
    use crate::service::protocol::{SERVICE_PROTOCOL_VERSION, StartTaskCommand};
    #[cfg(unix)]
    use crate::service::{client::ServiceClientErrorCode, client::TaskServiceClient};
    #[cfg(unix)]
    use rusqlite::Connection;
    #[cfg(unix)]
    use serde_json::json;

    #[cfg(unix)]
    #[tokio::test]
    async fn idle_maintenance_becomes_ready_without_provider_dispatch() {
        let layout = ShutdownTestLayout::new();
        let port_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            ..HandoffPortState::default()
        }));
        let service = TaskService::bind(&layout.data, HandoffPort::new(Arc::clone(&port_state)))
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let serve_cancellation = cancellation.clone();
        let service_task = tokio::spawn(async move { service.serve(serve_cancellation).await });
        let mut client = TaskServiceClient::connect(&layout.data).await.unwrap();

        let result = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "idle-maintenance-prepare".to_owned(),
                idempotency_key: "idle-maintenance-prepare-key".to_owned(),
                command: ServiceCommand::PrepareMaintenance,
            })
            .await
            .unwrap();
        assert_eq!(
            result,
            ServiceResult::Maintenance(ServiceMaintenanceStatus {
                schema_version: 1,
                phase: MaintenancePhase::Ready,
                task_id: None,
                checkpoint_id: None,
            })
        );
        {
            let state = port_state.lock().unwrap();
            assert_eq!(state.started_contexts, 0);
            assert_eq!(state.epoch, 0);
            assert_eq!(state.effect_count, 0);
            assert_eq!(state.shutdowns, 1);
        }

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), service_task)
            .await
            .expect("idle ready service exits on signal")
            .expect("service task did not panic")
            .expect("service exits cleanly");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_maintenance_drains_to_exact_checkpoint_and_denies_new_mutations() {
        let layout = ShutdownTestLayout::new();
        let port_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            release_on_boundary: true,
            continue_at_boundary: true,
            ..HandoffPortState::default()
        }));
        let service = TaskService::bind(&layout.data, HandoffPort::new(Arc::clone(&port_state)))
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let serve_cancellation = cancellation.clone();
        let service_task = tokio::spawn(async move { service.serve(serve_cancellation).await });
        let mut client = TaskServiceClient::connect(&layout.data).await.unwrap();
        let start = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "maintenance-active-start".to_owned(),
            idempotency_key: "maintenance-active-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "maintenance-active-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "drain this task after one exact operation".to_owned(),
                model: ModelId::parse("gpt-test").unwrap(),
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: crate::runtime::task::TaskBudget::default(),
            }),
        };
        let ServiceResult::Accepted { task_id } = client.request(start).await.unwrap() else {
            panic!("maintenance task was not accepted");
        };
        loop {
            let provider_ready = {
                let state = port_state.lock().unwrap();
                state.effect_count == 1 && state.operation_id.is_some()
            };
            if provider_ready {
                break;
            }
            tokio::task::yield_now().await;
        }
        let ServiceResult::Accepted {
            task_id: queued_task,
        } = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "maintenance-queued-start".to_owned(),
                idempotency_key: "maintenance-queued-start-key".to_owned(),
                command: ServiceCommand::StartTask(StartTaskCommand {
                    external_session_id: "maintenance-queued-session".to_owned(),
                    workspace: layout.workspace.clone(),
                    request: "remain queued during maintenance".to_owned(),
                    model: ModelId::parse("gpt-test").unwrap(),
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::FullAccess,
                    budget: crate::runtime::task::TaskBudget::default(),
                }),
            })
            .await
            .unwrap()
        else {
            panic!("queued maintenance task was not accepted");
        };

        let prepare_request = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "maintenance-prepare-1".to_owned(),
            idempotency_key: "maintenance-prepare-key".to_owned(),
            command: ServiceCommand::PrepareMaintenance,
        };
        let ServiceResult::Maintenance(preparing) =
            client.request(prepare_request.clone()).await.unwrap()
        else {
            panic!("prepare returned the wrong result");
        };
        assert_eq!(preparing.phase, MaintenancePhase::Draining);
        assert_eq!(preparing.task_id, Some(task_id));
        assert_eq!(preparing.checkpoint_id, None);

        let ready = loop {
            let result = client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("maintenance-poll-{}", uuid::Uuid::new_v4()),
                    idempotency_key: format!("maintenance-poll-key-{}", uuid::Uuid::new_v4()),
                    command: ServiceCommand::MaintenanceStatus,
                })
                .await
                .unwrap();
            let ServiceResult::Maintenance(status) = result else {
                panic!("status returned the wrong result");
            };
            if status.phase == MaintenancePhase::Ready {
                break status;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(ready.task_id, Some(task_id));
        assert!(ready.checkpoint_id.is_some());

        let mut replay = prepare_request;
        replay.request_id = "maintenance-prepare-replay".to_owned();
        drop(client);
        let mut client = TaskServiceClient::connect(&layout.data).await.unwrap();
        assert_eq!(
            client.request(replay).await.unwrap(),
            ServiceResult::Maintenance(preparing)
        );
        let fresh_prepare = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "maintenance-prepare-fresh".to_owned(),
                idempotency_key: "maintenance-prepare-fresh-key".to_owned(),
                command: ServiceCommand::PrepareMaintenance,
            })
            .await
            .unwrap_err();
        assert_eq!(fresh_prepare.code(), ServiceClientErrorCode::Rejected);
        assert_eq!(
            client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: "maintenance-read-info".to_owned(),
                    idempotency_key: "maintenance-read-info-key".to_owned(),
                    command: ServiceCommand::Info,
                })
                .await
                .unwrap(),
            ServiceResult::Info(client.info().clone())
        );
        let rejected = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "maintenance-rejected-resume".to_owned(),
                idempotency_key: "maintenance-rejected-resume-key".to_owned(),
                command: ServiceCommand::Resume { task_id },
            })
            .await
            .unwrap_err();
        assert_eq!(rejected.code(), ServiceClientErrorCode::Rejected);
        let ServiceResult::Snapshot(queued) = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "maintenance-queued-status".to_owned(),
                idempotency_key: "maintenance-queued-status-key".to_owned(),
                command: ServiceCommand::Status {
                    task_id: queued_task,
                },
            })
            .await
            .unwrap()
        else {
            panic!("queued status returned the wrong result");
        };
        assert_eq!(queued.status, TaskStatus::Queued);

        {
            let state = port_state.lock().unwrap();
            assert_eq!(state.effect_count, 1);
            assert_eq!(state.boundary_requests, 1);
            assert_eq!(state.epoch, 1, "one work epoch");
            assert_eq!(state.shutdowns, 1);
            assert_eq!(state.operations_after_shutdown, 0);
        }
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), service_task)
            .await
            .expect("ready service exits immediately on signal")
            .expect("service task did not panic")
            .expect("service exits cleanly");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn crash_while_draining_reopens_uncertain_without_duplicate_effect_dispatch() {
        let layout = ShutdownTestLayout::new();
        let port_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            ..HandoffPortState::default()
        }));
        let service = TaskService::bind(&layout.data, HandoffPort::new(Arc::clone(&port_state)))
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let service_task = tokio::spawn(async move { service.serve(cancellation).await });
        let mut client = TaskServiceClient::connect(&layout.data).await.unwrap();
        let ServiceResult::Accepted { task_id } = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "draining-crash-start".to_owned(),
                idempotency_key: "draining-crash-start-key".to_owned(),
                command: ServiceCommand::StartTask(StartTaskCommand {
                    external_session_id: "draining-crash-session".to_owned(),
                    workspace: layout.workspace.clone(),
                    request: "perform one consequential operation before maintenance".to_owned(),
                    model: ModelId::parse("gpt-test").unwrap(),
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::FullAccess,
                    budget: crate::runtime::task::TaskBudget::default(),
                }),
            })
            .await
            .unwrap()
        else {
            panic!("draining crash task was not accepted");
        };
        let operation_id = loop {
            let ready_operation = {
                let state = port_state.lock().unwrap();
                (state.effect_count == 1)
                    .then(|| state.operation_id.clone())
                    .flatten()
            };
            if let Some(operation_id) = ready_operation {
                break OperationId::from_uuid(uuid::Uuid::parse_str(&operation_id).unwrap());
            }
            tokio::task::yield_now().await;
        };
        let ServiceResult::Maintenance(status) = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "draining-crash-prepare".to_owned(),
                idempotency_key: "draining-crash-prepare-key".to_owned(),
                command: ServiceCommand::PrepareMaintenance,
            })
            .await
            .unwrap()
        else {
            panic!("draining crash prepare returned the wrong result");
        };
        assert_eq!(status.phase, MaintenancePhase::Draining);
        loop {
            if port_state.lock().unwrap().boundary_requests == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }

        service_task.abort();
        let aborted = service_task.await.unwrap_err();
        assert!(aborted.is_cancelled());
        drop(client);
        assert_eq!(port_state.lock().unwrap().effect_count, 1);

        let replacement_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            ..HandoffPortState::default()
        }));
        let replacement = TaskService::bind(
            &layout.data,
            HandoffPort::new(Arc::clone(&replacement_state)),
        )
        .await
        .unwrap();
        assert!(replacement.initial_tasks.is_empty());
        assert_eq!(replacement_state.lock().unwrap().effect_count, 0);
        let snapshot = Store::open(layout.data.join("carl.sqlite3"))
            .unwrap()
            .get_task(task_id)
            .unwrap()
            .unwrap()
            .snapshot;
        assert_eq!(snapshot.status, TaskStatus::Blocked);
        assert_eq!(
            snapshot.operation_status(operation_id),
            Some(OperationStatus::Uncertain)
        );
        drop(replacement);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signal_maintenance_quiesces_active_work_without_interrupting_it() {
        let layout = ShutdownTestLayout::new();
        let port_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            release_on_boundary: true,
            continue_at_boundary: true,
            ..HandoffPortState::default()
        }));
        let service = TaskService::bind(&layout.data, HandoffPort::new(Arc::clone(&port_state)))
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let serve_cancellation = cancellation.clone();
        let service_task = tokio::spawn(async move { service.serve(serve_cancellation).await });
        let mut client = TaskServiceClient::connect(&layout.data).await.unwrap();
        let ServiceResult::Accepted { task_id } = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "signal-maintenance-start".to_owned(),
                idempotency_key: "signal-maintenance-start-key".to_owned(),
                command: ServiceCommand::StartTask(StartTaskCommand {
                    external_session_id: "signal-maintenance-session".to_owned(),
                    workspace: layout.workspace.clone(),
                    request: "finish this operation at a safe boundary".to_owned(),
                    model: ModelId::parse("gpt-test").unwrap(),
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::FullAccess,
                    budget: crate::runtime::task::TaskBudget::default(),
                }),
            })
            .await
            .unwrap()
        else {
            panic!("signal maintenance task was not accepted");
        };
        loop {
            let provider_ready = {
                let state = port_state.lock().unwrap();
                state.effect_count == 1 && state.operation_id.is_some()
            };
            if provider_ready {
                break;
            }
            tokio::task::yield_now().await;
        }

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), service_task)
            .await
            .expect("signal maintenance timed out")
            .expect("service task did not panic")
            .expect("signal maintenance failed");
        drop(client);

        let snapshot = Store::open(layout.data.join("carl.sqlite3"))
            .unwrap()
            .get_task(task_id)
            .unwrap()
            .unwrap()
            .snapshot;
        assert_eq!(snapshot.status, TaskStatus::Active);
        assert!(snapshot.active_epoch.is_none());
        assert!(snapshot.latest_checkpoint.is_some());
        let completed_operation = {
            let state = port_state.lock().unwrap();
            assert_eq!(state.effect_count, 1);
            assert_eq!(state.boundary_requests, 1);
            assert_eq!(state.interrupts, 0);
            assert_eq!(state.shutdowns, 1);
            assert_eq!(state.operations_after_shutdown, 0);
            state.operation_id.clone().unwrap()
        };

        let replacement_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            completion_evidence_operation_id: Some(completed_operation),
            ..HandoffPortState::default()
        }));
        let replacement = TaskService::bind(
            &layout.data,
            HandoffPort::new(Arc::clone(&replacement_state)),
        )
        .await
        .unwrap();
        assert_eq!(replacement.initial_tasks, vec![task_id]);
        assert_eq!(replacement_state.lock().unwrap().effect_count, 0);
        let replacement_cancellation = CancellationToken::new();
        let replacement_serve_cancellation = replacement_cancellation.clone();
        let replacement_task =
            tokio::spawn(async move { replacement.serve(replacement_serve_cancellation).await });
        let mut replacement_client = TaskServiceClient::connect(&layout.data).await.unwrap();
        loop {
            let ServiceResult::Snapshot(snapshot) = replacement_client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("signal-reopen-status-{}", uuid::Uuid::new_v4()),
                    idempotency_key: format!("signal-reopen-key-{}", uuid::Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .unwrap()
            else {
                panic!("reopened task status returned the wrong result");
            };
            if snapshot.status == TaskStatus::Completed {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(replacement_state.lock().unwrap().effect_count, 0);
        replacement_cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), replacement_task)
            .await
            .expect("reopened service shutdown timed out")
            .expect("reopened service task panicked")
            .expect("reopened service shutdown failed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_handoff_cancels_before_provider_shutdown_and_preserves_queued_work() {
        let layout = ShutdownTestLayout::new();
        let port_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            ..HandoffPortState::default()
        }));
        let service = TaskService::bind(&layout.data, HandoffPort::new(Arc::clone(&port_state)))
            .await
            .unwrap();
        let TaskService {
            endpoint,
            engine,
            read_store,
            initial_tasks,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates,
            live_update_receiver,
            permission_receiver,
            next_acknowledgement,
            actor_state,
            info,
        } = service;
        let (actor_sender, actor_receiver) = mpsc::channel(SERVICE_COMMAND_CAPACITY);
        let actor_task = tokio::spawn(run_task_actor(
            engine,
            initial_tasks,
            actor_receiver,
            Arc::clone(&actor_state),
        ));
        let shared = Arc::new(ServiceShared {
            read_store,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates,
            next_acknowledgement,
            actor_state: Arc::clone(&actor_state),
            actor_sender,
            info,
        });

        let start = |suffix: &str| ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: format!("handoff-start-{suffix}"),
            idempotency_key: format!("handoff-start-{suffix}-key"),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: format!("handoff-{suffix}-session"),
                workspace: layout.workspace.clone(),
                request: format!("handoff {suffix} task"),
                model: ModelId::parse("gpt-test").unwrap(),
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: crate::runtime::task::TaskBudget::default(),
            }),
        };
        let ServiceResult::Accepted {
            task_id: active_task,
        } = dispatch_request(&shared, start("active")).await.unwrap()
        else {
            panic!("active handoff task was not accepted");
        };
        loop {
            let active = lock_store(&shared.read_store)
                .unwrap()
                .get_task(active_task)
                .unwrap()
                .unwrap()
                .snapshot;
            let provider_ready = {
                let state = port_state.lock().unwrap();
                state.effect_count == 1 && state.operation_id.is_some()
            };
            if active.status == TaskStatus::Active
                && active.active_epoch.is_some()
                && provider_ready
                && actor_state.active_task().await == Some(active_task)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let ServiceResult::Accepted {
            task_id: queued_task,
        } = dispatch_request(&shared, start("queued")).await.unwrap()
        else {
            panic!("queued handoff task was not accepted");
        };
        assert_eq!(
            lock_store(&shared.read_store)
                .unwrap()
                .get_task(queued_task)
                .unwrap()
                .unwrap()
                .snapshot
                .status,
            TaskStatus::Queued
        );

        let active_lock = actor_state.owner.lock().await;
        assert_eq!(active_lock.active_task, Some(active_task));
        let shutdown_request = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "handoff-shutdown".to_owned(),
            idempotency_key: "handoff-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        };
        let mut shutdown = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move { dispatch_request(&shared, shutdown_request).await }
        });

        let database = layout.data.join("carl.sqlite3");
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let claimed = Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM service_command_receipts
                 WHERE idempotency_key = 'handoff-shutdown-key' AND state = 'pending'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(
            claimed, 1,
            "shutdown receipt must precede owner publication"
        );
        assert!(!shutdown.is_finished());
        assert!(!active_lock.emergency_requested);

        port_state.lock().unwrap().release_completion = true;
        loop {
            let status = lock_store(&shared.read_store)
                .unwrap()
                .get_task(active_task)
                .unwrap()
                .unwrap()
                .snapshot
                .status;
            if status == TaskStatus::Completed {
                break;
            }
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        drop(active_lock);
        assert!(actor_state.starts_stopped().await);

        let outcome = tokio::time::timeout(Duration::from_secs(1), &mut shutdown).await;
        drop(shutdown);
        let provider = {
            let state = port_state.lock().unwrap();
            (state.shutdowns, state.operations_after_shutdown)
        };
        let connection = Connection::open(&database).unwrap();
        let (receipt_state, result_json) = connection
            .query_row(
                "SELECT state, result_json FROM service_command_receipts
                 WHERE idempotency_key = 'handoff-shutdown-key'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap();
        let pending = connection
            .query_row(
                "SELECT COUNT(*) FROM service_command_receipts WHERE state = 'pending'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        let queued_status = connection
            .query_row(
                "SELECT status FROM agent_tasks WHERE id = ?1",
                [queued_task.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        drop(connection);

        drop(shared);
        drop(live_update_receiver);
        drop(permission_receiver);
        let actor_result = tokio::time::timeout(Duration::from_secs(1), actor_task)
            .await
            .expect("handoff actor did not stop")
            .expect("handoff actor panicked");
        assert!(actor_result.is_ok());
        drop(endpoint);

        let replacement_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            ..HandoffPortState::default()
        }));
        let replacement = TaskService::bind(
            &layout.data,
            HandoffPort::new(Arc::clone(&replacement_state)),
        )
        .await
        .unwrap();
        assert_eq!(replacement.initial_tasks, vec![queued_task]);
        assert_eq!(replacement_state.lock().unwrap().started_contexts, 1);
        drop(replacement);

        assert!(
            matches!(outcome, Ok(Ok(Ok(ServiceResult::Applied)))),
            "terminal handoff failed: outcome={outcome:?}, provider={provider:?}, receipt={receipt_state}, pending={pending}, queued={queued_status}"
        );
        assert_eq!(provider, (1, 0));
        assert_eq!(receipt_state, "completed");
        assert!(
            result_json
                .as_deref()
                .is_some_and(|result| serde_json::from_str::<serde_json::Value>(result).is_ok())
        );
        assert_eq!(pending, 0);
        assert_eq!(queued_status, "queued");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signal_shutdown_waits_for_an_admitted_mutation_to_finish() {
        let layout = ShutdownTestLayout::new();
        let port_state = Arc::new(Mutex::new(HandoffPortState {
            workspace: layout.workspace.clone(),
            ..HandoffPortState::default()
        }));
        let service = TaskService::bind(&layout.data, HandoffPort::new(Arc::clone(&port_state)))
            .await
            .unwrap();
        let TaskService {
            endpoint,
            engine,
            read_store,
            initial_tasks,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates,
            live_update_receiver,
            permission_receiver,
            next_acknowledgement,
            actor_state,
            info,
        } = service;
        let (actor_sender, actor_receiver) = mpsc::channel(SERVICE_COMMAND_CAPACITY);
        let actor_task = tokio::spawn(run_task_actor(
            engine,
            initial_tasks,
            actor_receiver,
            Arc::clone(&actor_state),
        ));
        let shared = Arc::new(ServiceShared {
            read_store,
            controls,
            acknowledgements,
            mutation_gate,
            live_updates,
            next_acknowledgement,
            actor_state,
            actor_sender,
            info,
        });
        let receipt = ServiceCommandReceiptInput {
            idempotency_key: "signal-admitted-mutation".to_owned(),
            command_digest: Sha256Digest::from_bytes([0x5a; 32]),
            command_kind: "cancel".to_owned(),
            created_at: Utc::now(),
        };
        assert_eq!(
            claim_service_command(&shared, receipt.clone())
                .await
                .unwrap(),
            ServiceCommandReceiptClaim::Fresh
        );

        // Holding this guard models a mutation that passed admission and owns the
        // service's serialization boundary while it finishes its durable receipt.
        let mutation_guard = shared.mutation_gate.lock().await;
        let signal_shared = Arc::clone(&shared);
        let signal_shutdown =
            tokio::spawn(async move { shutdown_owner_after_mutations(&signal_shared).await });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            port_state.lock().unwrap().shutdowns,
            0,
            "signal shutdown bypassed an admitted mutation"
        );

        complete_service_command(
            &shared,
            receipt,
            serde_json::to_string(&ServiceResult::Applied).unwrap(),
        )
        .await
        .unwrap();
        drop(mutation_guard);
        tokio::time::timeout(Duration::from_secs(1), signal_shutdown)
            .await
            .expect("serialized signal shutdown timed out")
            .expect("serialized signal shutdown task panicked")
            .expect("serialized signal shutdown failed");

        let database = layout.data.join("carl.sqlite3");
        let connection = Connection::open(&database).unwrap();
        let (receipt_state, pending) = connection
            .query_row(
                "SELECT state, (SELECT COUNT(*) FROM service_command_receipts WHERE state = 'pending')
                 FROM service_command_receipts WHERE idempotency_key = 'signal-admitted-mutation'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap();
        drop(connection);
        assert_eq!(receipt_state, "completed");
        assert_eq!(pending, 0);
        assert_eq!(
            {
                let state = port_state.lock().unwrap();
                (state.shutdowns, state.operations_after_shutdown)
            },
            (1, 0)
        );

        drop(shared);
        drop(live_update_receiver);
        drop(permission_receiver);
        tokio::time::timeout(Duration::from_secs(1), actor_task)
            .await
            .expect("signal shutdown actor did not stop")
            .expect("signal shutdown actor panicked")
            .expect("signal shutdown actor failed");
        drop(endpoint);
    }

    #[test]
    fn shutdown_cancellation_routes_terminal_active_and_inactive_transitions() {
        let task_id = TaskId::new();
        for status in [
            TaskStatus::Cancelled,
            TaskStatus::Completed,
            TaskStatus::Failed,
        ] {
            assert_eq!(
                classify_shutdown_cancel(status, Some(task_id), task_id).unwrap(),
                ShutdownCancelRoute::Quiesced
            );
        }
        assert_eq!(
            classify_shutdown_cancel(TaskStatus::Active, Some(task_id), task_id).unwrap(),
            ShutdownCancelRoute::Active
        );
        for status in [TaskStatus::Active, TaskStatus::Paused, TaskStatus::Blocked] {
            assert_eq!(
                classify_shutdown_cancel(status, None, task_id).unwrap(),
                ShutdownCancelRoute::Idle
            );
        }
        assert_eq!(
            classify_shutdown_cancel(TaskStatus::Active, Some(TaskId::new()), task_id)
                .unwrap_err()
                .code(),
            TaskServiceErrorCode::Busy
        );
    }

    #[tokio::test]
    async fn published_shutdown_wins_before_task_start_claim() {
        let actor_state = TaskActorState::default();
        let task_id = TaskId::new();
        assert_eq!(actor_state.publish_shutdown().await, None);
        assert!(!actor_state.claim_start(task_id).await);
        assert_eq!(actor_state.active_task().await, None);
    }

    #[tokio::test]
    async fn task_start_claim_wins_before_shutdown_publication() {
        let actor_state = TaskActorState::default();
        let task_id = TaskId::new();
        assert!(actor_state.claim_start(task_id).await);
        assert_eq!(actor_state.publish_shutdown().await, Some(task_id));
        assert_eq!(actor_state.active_task().await, Some(task_id));
    }

    #[tokio::test]
    async fn published_shutdown_rejects_resume_without_enqueuing() {
        let actor_state = TaskActorState::default();
        actor_state.publish_shutdown().await;
        let mut scheduled = VecDeque::new();
        let task_id = TaskId::new();

        let error = enqueue_resumed_task(&actor_state, false, &mut scheduled, task_id)
            .await
            .expect_err("resume after shutdown must be rejected");

        assert_eq!(error.code(), TaskServiceErrorCode::Stopped);
        assert!(scheduled.is_empty());
    }

    #[tokio::test]
    async fn shutdown_retry_remembers_the_task_observed_before_handoff() {
        let actor_state = TaskActorState::default();
        let task_id = TaskId::new();
        assert!(actor_state.claim_start(task_id).await);
        assert_eq!(actor_state.publish_shutdown().await, Some(task_id));
        actor_state.owner.lock().await.active_task = None;

        assert_eq!(actor_state.publish_shutdown().await, Some(task_id));
    }

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

    #[tokio::test(start_paused = true)]
    async fn empty_live_polls_unregister_without_accumulating_senders() {
        let task_id = TaskId::new();
        let hub = LiveUpdateHub::new(Arc::new(AtomicU64::new(0)));

        for _ in 0..10_000 {
            let (updates, cursor, overflowed) = hub.page(task_id, None, 128).await.unwrap();
            assert!(updates.is_empty());
            assert_eq!(cursor, None);
            assert!(!overflowed);
        }
        {
            let tasks = hub.tasks.lock().unwrap();
            let task = tasks.get(&task_id).unwrap();
            assert_eq!(task.subscribers.len(), 0);
            assert!(task.ring.is_empty());
        }

        let mut waiter = Box::pin(hub.page(task_id, None, 128));
        tokio::select! {
            biased;
            result = &mut waiter => panic!("live poll returned before publish: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        hub.publish(
            task_id,
            TaskUpdate::AssistantDelta("after empty polls".to_owned()),
        );
        let (updates, cursor, overflowed) = waiter.await.unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(cursor, Some(1));
        assert!(!overflowed);
    }

    #[test]
    fn foreign_generation_cursor_cannot_skip_replacement_live_update_types() {
        let task_id = TaskId::new();
        let mut task = LiveTaskUpdates::default();
        task.ring.extend([
            LiveUpdateEnvelope {
                cursor: 1,
                update: TaskUpdate::AssistantDelta("replacement assistant".to_owned()),
            },
            LiveUpdateEnvelope {
                cursor: 2,
                update: TaskUpdate::Diff("replacement diff".to_owned()),
            },
            LiveUpdateEnvelope {
                cursor: 3,
                update: TaskUpdate::ApprovalRequired {
                    task_id,
                    operation_id: OperationId::new(),
                    display_code: "654321".to_owned(),
                    summary: "replacement approval".to_owned(),
                    request_id: "replacement-request".to_owned(),
                    session_id: SessionId::new(),
                    turn_id: TurnId::new(),
                    external_session_id: "replacement-session".to_owned(),
                },
            },
        ]);

        let cursor = live_after_cursor("old-generation", "new-generation", Some(3));
        let (updates, cursor, overflowed) = task.page(cursor, 128, 0);
        assert_eq!(updates.len(), 3);
        assert_eq!(cursor, Some(3));
        assert!(!overflowed);
        assert!(matches!(updates[0].update, TaskUpdate::AssistantDelta(_)));
        assert!(matches!(updates[1].update, TaskUpdate::Diff(_)));
        assert!(matches!(
            updates[2].update,
            TaskUpdate::ApprovalRequired { .. }
        ));

        let cursor = live_after_cursor("new-generation", "new-generation", cursor);
        let (updates, cursor, overflowed) = task.page(cursor, 128, 0);
        assert!(updates.is_empty());
        assert_eq!(cursor, Some(3));
        assert!(!overflowed);
    }

    #[cfg(unix)]
    struct ShutdownTestLayout {
        root: PathBuf,
        data: PathBuf,
        workspace: PathBuf,
    }

    #[cfg(unix)]
    impl ShutdownTestLayout {
        fn new() -> Self {
            let root = PathBuf::from("/tmp").join(format!(
                "carl-shutdown-handoff-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
            let data = root.join("data");
            let workspace = root.join("workspace");
            fs::create_dir_all(&data).unwrap();
            fs::create_dir_all(&workspace).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self {
                root,
                data: fs::canonicalize(data).unwrap(),
                workspace: fs::canonicalize(workspace).unwrap(),
            }
        }
    }

    #[cfg(unix)]
    impl Drop for ShutdownTestLayout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    struct HandoffPort {
        state: Arc<Mutex<HandoffPortState>>,
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct HandoffPortState {
        workspace: PathBuf,
        events: VecDeque<AgentEvent>,
        active_context: Option<AgentContextId>,
        active_epoch: Option<AgentEpochId>,
        epoch: u64,
        effect_count: u64,
        operation_id: Option<String>,
        release_completion: bool,
        release_on_boundary: bool,
        continue_at_boundary: bool,
        boundary_requests: u64,
        interrupts: u64,
        completion_emitted: bool,
        completion_evidence_operation_id: Option<String>,
        started_contexts: u64,
        shutdowns: u64,
        provider_shutdown: bool,
        operations_after_shutdown: u64,
    }

    #[cfg(unix)]
    impl HandoffPort {
        fn new(state: Arc<Mutex<HandoffPortState>>) -> Self {
            Self { state }
        }

        fn note_operation(&self) {
            let mut state = self.state.lock().unwrap();
            if state.provider_shutdown {
                state.operations_after_shutdown += 1;
            }
        }
    }

    #[cfg(unix)]
    impl AgentPort for HandoffPort {
        fn supports_autonomous_tasks(&self) -> bool {
            true
        }

        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities {
                resume: true,
                compact: true,
                token_usage: false,
                pre_dispatch_effects: true,
                history_paging: false,
                background_processes: false,
            }
        }

        fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
            self.note_operation();
            Box::pin(async {
                Ok(vec![AgentModel {
                    id: ModelId::parse("gpt-test").expect("test model is valid"),
                    display_name: "GPT Test".to_owned(),
                    supported_efforts: vec![ReasoningEffort::High],
                    default_effort: ReasoningEffort::High,
                }])
            })
        }

        fn start_context(
            &mut self,
            _request: StartAgentContext,
        ) -> AgentFuture<'_, AgentContextId> {
            self.note_operation();
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                let mut state = state.lock().unwrap();
                state.started_contexts += 1;
                AgentContextId::parse(format!("handoff-context-{}", state.started_contexts))
            })
        }

        fn resume_context(
            &mut self,
            request: ResumeAgentContext,
        ) -> AgentFuture<'_, AgentContextId> {
            self.note_operation();
            Box::pin(async move { Ok(request.context_id) })
        }

        fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
            self.note_operation();
            Box::pin(async { Ok(()) })
        }

        fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
            self.note_operation();
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                let mut state = state.lock().unwrap();
                state.epoch += 1;
                let epoch_id = AgentEpochId::parse(format!("handoff-epoch-{}", state.epoch))?;
                state.events.push_back(AgentEvent::EpochStarted {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                });
                if request.permission_mode == PermissionMode::Plan {
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: request.context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text: "<carl-completion-contract>{\"version\":1,\"goal\":\"Complete before shutdown cancellation\",\"constraints\":[],\"clauses\":[{\"id\":\"requested-outcome\",\"description\":\"Requested outcome\",\"required\":true,\"status\":\"pending\",\"evidence\":[]},{\"id\":\"explicit-verification\",\"description\":\"Explicit verification\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".to_owned(),
                    });
                    state.events.push_back(AgentEvent::EpochCompleted {
                        context_id: request.context_id,
                        epoch_id: epoch_id.clone(),
                        status: "completed".to_owned(),
                    });
                } else {
                    state.active_context = Some(request.context_id.clone());
                    state.active_epoch = Some(epoch_id.clone());
                    if let Some(operation_id) = state.completion_evidence_operation_id.clone() {
                        state.events.push_back(AgentEvent::AssistantDelta {
                            context_id: request.context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            text: format!(
                                "<carl-epoch-report>{}</carl-epoch-report>",
                                json!({
                                    "schema_version": 1,
                                    "disposition": "complete",
                                    "summary": "resumed from the committed maintenance checkpoint",
                                    "clause_evidence": [
                                        {"clause_id":"requested-outcome","operation_ids":[operation_id.clone()],"event_sequences":[],"artifact_digests":[]},
                                        {"clause_id":"explicit-verification","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]}
                                    ],
                                    "exact_identifiers": []
                                })
                            ),
                        });
                        state.events.push_back(AgentEvent::EpochCompleted {
                            context_id: request.context_id,
                            epoch_id,
                            status: "completed".to_owned(),
                        });
                        return Ok(state.active_epoch.clone().unwrap());
                    }
                    let item = AgentItem::Command {
                        item_id: "handoff-effect".to_owned(),
                        command: "finish-before-cancel".to_owned(),
                        cwd: state.workspace.clone(),
                        status: "inProgress".to_owned(),
                        exit_code: None,
                        aggregated_output: None,
                        process_id: None,
                    };
                    state.events.push_back(AgentEvent::ItemStarted {
                        context_id: request.context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item,
                    });
                    state
                        .events
                        .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                            context_id: request.context_id,
                            epoch_id: epoch_id.clone(),
                            request_id: AgentRequestId::parse("handoff-effect-request")?,
                            item_id: "handoff-effect".to_owned(),
                            kind: AgentEffectKind::Command,
                            summary: "finish before cancellation dispatch".to_owned(),
                            request_digest: Sha256Digest::parse("5".repeat(64))
                                .expect("literal digest is valid"),
                        }));
                }
                Ok(epoch_id)
            })
        }

        fn steer(
            &mut self,
            _context_id: &AgentContextId,
            _epoch_id: &AgentEpochId,
            text: String,
        ) -> AgentFuture<'_, ()> {
            self.note_operation();
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                if let Some(operation_id) = text.strip_prefix("carl-operation-id:") {
                    state.lock().unwrap().operation_id = Some(operation_id.trim().to_owned());
                } else if text.starts_with("Carl soft epoch boundary") {
                    let mut state = state.lock().unwrap();
                    state.boundary_requests += 1;
                    if state.release_on_boundary {
                        state.release_completion = true;
                    }
                }
                Ok(())
            })
        }

        fn interrupt(
            &mut self,
            _context_id: &AgentContextId,
            _epoch_id: &AgentEpochId,
        ) -> AgentFuture<'_, ()> {
            self.note_operation();
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                state.lock().unwrap().interrupts += 1;
                Ok(())
            })
        }

        fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
            self.note_operation();
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                loop {
                    {
                        let mut state = state.lock().unwrap();
                        if let Some(event) = state.events.pop_front() {
                            return Ok(event);
                        }
                        if state.release_completion
                            && !state.completion_emitted
                            && state.effect_count == 1
                            && let Some(operation_id) = state.operation_id.clone()
                        {
                            state.completion_emitted = true;
                            let context_id = state
                                .active_context
                                .clone()
                                .expect("work context was installed");
                            let epoch_id = state
                                .active_epoch
                                .clone()
                                .expect("work epoch was installed");
                            let workspace = state.workspace.clone();
                            state.events.push_back(AgentEvent::ItemCompleted {
                                context_id: context_id.clone(),
                                epoch_id: epoch_id.clone(),
                                item: AgentItem::Command {
                                    item_id: "handoff-effect".to_owned(),
                                    command: "finish-before-cancel".to_owned(),
                                    cwd: workspace,
                                    status: "completed".to_owned(),
                                    exit_code: Some(0),
                                    aggregated_output: Some("completed before cancel".to_owned()),
                                    process_id: None,
                                },
                            });
                            let disposition = if state.continue_at_boundary {
                                "continue"
                            } else {
                                "complete"
                            };
                            let next_objective =
                                state.continue_at_boundary.then_some("finish after restart");
                            let clause_evidence = if state.continue_at_boundary {
                                json!([])
                            } else {
                                json!([
                                    {"clause_id":"requested-outcome","operation_ids":[operation_id.clone()],"event_sequences":[],"artifact_digests":[]},
                                    {"clause_id":"explicit-verification","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]}
                                ])
                            };
                            state.events.push_back(AgentEvent::AssistantDelta {
                                context_id: context_id.clone(),
                                epoch_id: epoch_id.clone(),
                                text: format!(
                                    "<carl-epoch-report>{}</carl-epoch-report>",
                                    json!({
                                        "schema_version": 1,
                                        "disposition": disposition,
                                        "summary": "completed naturally during shutdown handoff",
                                        "next_objective": next_objective,
                                        "clause_evidence": clause_evidence,
                                        "exact_identifiers": []
                                    })
                                ),
                            });
                            state.events.push_back(AgentEvent::EpochCompleted {
                                context_id,
                                epoch_id,
                                status: "completed".to_owned(),
                            });
                            continue;
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
        }

        fn resolve_effect(
            &mut self,
            _request_id: &AgentRequestId,
            decision: EffectDecision,
        ) -> AgentFuture<'_, ()> {
            self.note_operation();
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                if decision == EffectDecision::Allow {
                    state.lock().unwrap().effect_count += 1;
                }
                Ok(())
            })
        }

        fn list_background_processes(
            &mut self,
            _context_id: &AgentContextId,
        ) -> AgentFuture<'_, Vec<AgentProcess>> {
            self.note_operation();
            Box::pin(async { Ok(Vec::new()) })
        }

        fn terminate_background_process(
            &mut self,
            _context_id: &AgentContextId,
            _process_id: &str,
        ) -> AgentFuture<'_, bool> {
            self.note_operation();
            Box::pin(async { Ok(true) })
        }

        fn shutdown(&mut self) -> AgentFuture<'_, ()> {
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                let mut state = state.lock().unwrap();
                state.shutdowns += 1;
                state.provider_shutdown = true;
                Ok(())
            })
        }
    }
}
