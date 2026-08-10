//! Bounded Agent Client Protocol framing and session configuration.

mod buzz;
mod config;
mod protocol;

pub use buzz::{
    BuzzContext, BuzzError, BuzzErrorCode, BuzzPublisher, BuzzPublisherConfig,
    leading_slash_command,
};
pub use config::{
    ConfigChange, ConfigError, ConfigErrorCode, ModeActivation, ModelCatalog, ModelDescriptor,
    PermissionMode, SessionConfiguration, config_options,
};
pub use protocol::{
    AcpError, AcpErrorCode, BoundedJsonRpcString, IncomingFrame, JsonRpcId, OutgoingFrame,
    read_frame, write_frame,
};
