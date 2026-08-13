mod command;
mod filesystem;

use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::acp::PermissionMode;
use crate::providers::ToolDefinition;

use self::command::CommandAction;
use self::filesystem::{ListAction, PatchAction, ReadAction, SearchAction};

const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolEffectKind {
    Read,
    Write,
    Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeToolErrorCode {
    UnknownTool,
    InvalidArguments,
    UnsafePath,
    PermissionDenied,
    WorkspaceChanged,
    SecretDetected,
    OutputTooLarge,
    CommandFailed,
    TimedOut,
    Cancelled,
    Io,
}

#[derive(Clone, Eq, Error, PartialEq)]
#[error("native coding tool failed")]
pub struct NativeToolError {
    code: NativeToolErrorCode,
}

impl NativeToolError {
    pub(crate) const fn new(code: NativeToolErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> NativeToolErrorCode {
        self.code
    }
}

impl fmt::Debug for NativeToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeToolError")
            .field("code", &self.code)
            .finish()
    }
}

pub struct NativeToolRuntime {
    workspace: PathBuf,
    permission: PermissionMode,
    definitions: Vec<ToolDefinition>,
}

impl NativeToolRuntime {
    pub fn new(
        workspace: impl AsRef<Path>,
        permission: PermissionMode,
    ) -> Result<Self, NativeToolError> {
        let workspace = std::fs::canonicalize(workspace).map_err(|_| io_error())?;
        if !workspace.is_absolute()
            || !std::fs::metadata(&workspace)
                .map_err(|_| io_error())?
                .is_dir()
        {
            return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
        }
        Ok(Self {
            workspace,
            permission,
            definitions: definitions(),
        })
    }

    #[must_use]
    pub fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    pub fn prepare(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<PreparedNativeTool, NativeToolError> {
        let encoded = serde_json::to_vec(&arguments).map_err(|_| invalid_arguments())?;
        if encoded.len() > MAX_ARGUMENT_BYTES {
            return Err(invalid_arguments());
        }
        let action = match name {
            "read_file" => {
                PreparedAction::Read(ReadAction::prepare(&self.workspace, decode(arguments)?)?)
            }
            "list_directory" => {
                PreparedAction::List(ListAction::prepare(&self.workspace, decode(arguments)?)?)
            }
            "search_text" => {
                PreparedAction::Search(SearchAction::prepare(&self.workspace, decode(arguments)?)?)
            }
            "apply_patch" => {
                self.require_mutation_permission()?;
                PreparedAction::Patch(PatchAction::prepare(&self.workspace, decode(arguments)?)?)
            }
            "run_command" => {
                self.require_command_permission()?;
                PreparedAction::Command(CommandAction::prepare(
                    &self.workspace,
                    decode(arguments)?,
                )?)
            }
            _ => return Err(NativeToolError::new(NativeToolErrorCode::UnknownTool)),
        };
        let effect = action.effect_kind();
        let summary = action.summary();
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(encoded);
        hasher.update([effect as u8]);
        let digest = format!("sha256:{:x}", hasher.finalize());
        Ok(PreparedNativeTool {
            name: name.to_owned(),
            digest,
            summary,
            action,
        })
    }

    fn require_mutation_permission(&self) -> Result<(), NativeToolError> {
        if self.permission == PermissionMode::Plan || self.permission == PermissionMode::DontAsk {
            Err(NativeToolError::new(NativeToolErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }

    fn require_command_permission(&self) -> Result<(), NativeToolError> {
        if self.permission == PermissionMode::Plan || self.permission == PermissionMode::DontAsk {
            Err(NativeToolError::new(NativeToolErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

pub struct PreparedNativeTool {
    name: String,
    digest: String,
    summary: String,
    action: PreparedAction,
}

impl PreparedNativeTool {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn effect_kind(&self) -> ToolEffectKind {
        self.action.effect_kind()
    }

    pub async fn execute(self, cancellation: CancellationToken) -> Result<Value, NativeToolError> {
        if cancellation.is_cancelled() {
            return Err(NativeToolError::new(NativeToolErrorCode::Cancelled));
        }
        match self.action {
            PreparedAction::Read(action) => action.execute(cancellation).await,
            PreparedAction::List(action) => action.execute(cancellation).await,
            PreparedAction::Search(action) => action.execute(cancellation).await,
            PreparedAction::Patch(action) => action.execute(cancellation).await,
            PreparedAction::Command(action) => action.execute(cancellation).await,
        }
    }
}

impl fmt::Debug for PreparedNativeTool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNativeTool")
            .field("name", &self.name)
            .field("digest", &self.digest)
            .field("effect_kind", &self.effect_kind())
            .finish_non_exhaustive()
    }
}

enum PreparedAction {
    Read(ReadAction),
    List(ListAction),
    Search(SearchAction),
    Patch(PatchAction),
    Command(CommandAction),
}

impl PreparedAction {
    const fn effect_kind(&self) -> ToolEffectKind {
        match self {
            Self::Read(_) | Self::List(_) | Self::Search(_) => ToolEffectKind::Read,
            Self::Patch(_) => ToolEffectKind::Write,
            Self::Command(_) => ToolEffectKind::Command,
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Read(action) => action.summary(),
            Self::List(action) => action.summary(),
            Self::Search(action) => action.summary(),
            Self::Patch(action) => action.summary(),
            Self::Command(action) => action.summary(),
        }
    }
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, NativeToolError> {
    serde_json::from_value(value).map_err(|_| invalid_arguments())
}

fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "read_file".to_owned(),
            description: "Read a bounded UTF-8 workspace file, optionally by line range."
                .to_owned(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1}},"required":["path"],"additionalProperties":false}),
        },
        ToolDefinition {
            name: "list_directory".to_owned(),
            description: "List one workspace directory without following links.".to_owned(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}),
        },
        ToolDefinition {
            name: "search_text".to_owned(),
            description: "Search bounded UTF-8 workspace files with a literal or regex query."
                .to_owned(),
            input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"path":{"type":"string"},"regex":{"type":"boolean"}},"required":["query","path"],"additionalProperties":false}),
        },
        ToolDefinition {
            name: "apply_patch".to_owned(),
            description: "Apply exact, structured text replacements to workspace files.".to_owned(),
            input_schema: json!({"type":"object","properties":{"changes":{"type":"array","maxItems":128,"items":{"type":"object","properties":{"path":{"type":"string"},"find":{"type":"string"},"replace":{"type":"string"}},"required":["path","find","replace"],"additionalProperties":false}}},"required":["changes"],"additionalProperties":false}),
        },
        ToolDefinition {
            name: "run_command".to_owned(),
            description: "Run one bounded argv command without a shell or ambient environment."
                .to_owned(),
            input_schema: json!({"type":"object","properties":{"argv":{"type":"array","minItems":1,"maxItems":128,"items":{"type":"string"}},"timeout_seconds":{"type":"integer","minimum":1,"maximum":120}},"required":["argv"],"additionalProperties":false}),
        },
    ]
}

pub(crate) const fn invalid_arguments() -> NativeToolError {
    NativeToolError::new(NativeToolErrorCode::InvalidArguments)
}

pub(crate) const fn io_error() -> NativeToolError {
    NativeToolError::new(NativeToolErrorCode::Io)
}
