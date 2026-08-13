use crate::cli::{ExitClassification, TuiArgs};

pub mod command;
pub mod state;

/// Run Carl's interactive terminal frontend.
///
/// The terminal controller is added in the following implementation tasks. This
/// typed failure keeps CLI dispatch honest while the UI is being built.
pub async fn run(_args: TuiArgs) -> ExitClassification {
    ExitClassification::Failure
}
