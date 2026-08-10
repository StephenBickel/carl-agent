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
    PermissionMode, SessionConfiguration, config_options,
};
pub use kernel::{
    CodexPort, Kernel, KernelCommand, KernelHandle, KernelPublisher, PortFuture, PublicationFailure,
};
pub use protocol::{
    AcpError, AcpErrorCode, BoundedJsonRpcString, IncomingFrame, JsonRpcId, OutgoingFrame,
    read_frame, write_frame,
};
pub use server::{
    AcpServer, AcpServerConfig, AcpServerError, AcpServerErrorCode, BuzzPublisherBootstrap,
};
pub use session::{
    ConfigOutcome, ConfigSelection, KernelError, KernelErrorCode, KernelSession, KernelUpdate,
    NewSessionRequest, Prompt, PromptOutcome, PromptStopReason, ToolKind, ToolStatus,
};
