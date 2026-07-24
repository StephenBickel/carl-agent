use std::io::{self, Write};
use std::process::ExitCode;

use carl::cli::{Cli, ExitClassification, run_command};
use clap::Parser;

fn main() -> ExitCode {
    let command = Cli::parse().command;
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::from(1),
    };
    let result = runtime.block_on(run_command(command));

    let stdout_result = {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        stdout
            .write_all(result.stdout().as_bytes())
            .and_then(|()| stdout.flush())
    };
    let stderr_result = {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        stderr
            .write_all(result.stderr().as_bytes())
            .and_then(|()| stderr.flush())
    };
    if stdout_result.is_err() || stderr_result.is_err() {
        return ExitCode::from(1);
    }

    ExitCode::from(match result.exit_classification() {
        ExitClassification::Success => 0,
        ExitClassification::Failure => 1,
        ExitClassification::Cancelled => 130,
    })
}
