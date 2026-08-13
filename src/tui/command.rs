use thiserror::Error;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::service::protocol::MAX_TASK_TEXT_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlashCommand {
    Model(Option<String>),
    Provider(Option<String>),
    Effort(ReasoningEffort),
    Permissions(PermissionMode),
    Compact,
    New,
    Sessions,
    Resume(String),
    Status,
    Cancel,
    Login,
    Logout,
    Help,
    Exit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmittedInput {
    Prompt(String),
    Command(SlashCommand),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("TUI input is invalid")]
pub struct TuiInputError;

pub fn parse_submission(input: &str) -> Result<SubmittedInput, TuiInputError> {
    if input.is_empty()
        || input.trim().is_empty()
        || input.len() > MAX_TASK_TEXT_BYTES
        || input.contains('\0')
    {
        return Err(TuiInputError);
    }
    if !input.starts_with('/') {
        return Ok(SubmittedInput::Prompt(input.to_owned()));
    }
    if input.chars().any(|character| character.is_control()) {
        return Err(TuiInputError);
    }
    let parts = input.split_ascii_whitespace().collect::<Vec<_>>();
    let command = match parts.as_slice() {
        ["/model"] => SlashCommand::Model(None),
        ["/model", model] => {
            ModelId::parse((*model).to_owned()).map_err(|_| TuiInputError)?;
            SlashCommand::Model(Some((*model).to_owned()))
        }
        ["/provider"] => SlashCommand::Provider(None),
        ["/provider", provider] if valid_identifier(provider) => {
            SlashCommand::Provider(Some((*provider).to_owned()))
        }
        ["/effort", effort] => SlashCommand::Effort(parse_effort(effort)?),
        ["/permissions", permission] => SlashCommand::Permissions(parse_permission(permission)?),
        ["/compact"] => SlashCommand::Compact,
        ["/new"] => SlashCommand::New,
        ["/sessions"] => SlashCommand::Sessions,
        ["/resume", target] if valid_identifier(target) => {
            SlashCommand::Resume((*target).to_owned())
        }
        ["/status"] => SlashCommand::Status,
        ["/cancel"] => SlashCommand::Cancel,
        ["/login"] => SlashCommand::Login,
        ["/logout"] => SlashCommand::Logout,
        ["/help"] => SlashCommand::Help,
        ["/exit"] => SlashCommand::Exit,
        _ => return Err(TuiInputError),
    };
    Ok(SubmittedInput::Command(command))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn parse_effort(value: &str) -> Result<ReasoningEffort, TuiInputError> {
    match value {
        "low" => Ok(ReasoningEffort::Low),
        "medium" => Ok(ReasoningEffort::Medium),
        "high" => Ok(ReasoningEffort::High),
        "xhigh" => Ok(ReasoningEffort::XHigh),
        "max" => Ok(ReasoningEffort::Max),
        "ultra" => Ok(ReasoningEffort::Ultra),
        _ => Err(TuiInputError),
    }
}

fn parse_permission(value: &str) -> Result<PermissionMode, TuiInputError> {
    match value {
        "plan" => Ok(PermissionMode::Plan),
        "default" => Ok(PermissionMode::Default),
        "accept-edits" => Ok(PermissionMode::AcceptEdits),
        "dont-ask" => Ok(PermissionMode::DontAsk),
        "full-access" => Ok(PermissionMode::FullAccess),
        _ => Err(TuiInputError),
    }
}
