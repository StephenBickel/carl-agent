//! Bounded Agent Client Protocol framing and session configuration.

mod buzz;
mod config;
mod kernel;
mod protocol;
mod server;
mod session;

pub use buzz::{
    BuzzContext, BuzzError, BuzzErrorCode, BuzzPublisher, BuzzPublisherConfig,
    leading_slash_command,
};
pub use config::{
    ConfigChange, ConfigError, ConfigErrorCode, ModeActivation, ModelCatalog, ModelDescriptor,
    PermissionMode, PermissionProfile, SessionConfiguration, config_options,
};
pub use kernel::{Kernel, KernelCommand, KernelHandle, KernelPublisher, PublicationFailure};
pub use protocol::{
    AcpError, AcpErrorCode, BoundedJsonRpcString, IncomingFrame, JsonRpcId, OutgoingFrame,
    read_frame, write_frame,
};
pub use server::{
    AcpServer, AcpServerConfig, AcpServerError, AcpServerErrorCode, BuzzPublisherBootstrap,
    ServiceAcpServer,
};
pub use session::{
    ConfigOutcome, ConfigSelection, KernelError, KernelErrorCode, KernelSession, KernelUpdate,
    NewSessionRequest, Prompt, PromptOutcome, PromptStopReason, TaskContextView, TaskView,
    ToolKind, ToolStatus,
};
