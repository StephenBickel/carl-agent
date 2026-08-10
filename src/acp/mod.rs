//! Bounded Agent Client Protocol framing and session configuration.

mod config;
mod protocol;

pub use config::{
    ConfigChange, ConfigError, ConfigErrorCode, ModeActivation, ModelCatalog, ModelDescriptor,
    PermissionMode, SessionConfiguration, config_options,
};
pub use protocol::{
    AcpError, AcpErrorCode, BoundedJsonRpcString, IncomingFrame, JsonRpcId, OutgoingFrame,
    read_frame, write_frame,
};
