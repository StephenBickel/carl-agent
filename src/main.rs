use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use carl::cli::{Cli, Command, ExitClassification, run_acp_stdio, run_buzz_mcp_stdio, run_command};
use clap::Parser;

fn main() -> ExitCode {
    let buzz_mcp = env::args_os()
        .next()
        .and_then(|path| {
            std::path::PathBuf::from(path)
                .file_name()
                .map(ToOwned::to_owned)
        })
        .and_then(|name| name.to_str().map(str::to_owned))
        .is_some_and(|name| matches!(name.as_str(), "carl-buzz-mcp" | "carl-buzz-mcp.exe"));
    let command = if buzz_mcp {
        None
    } else {
        Some(Cli::parse().command)
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::from(1),
    };
    if buzz_mcp {
        return exit_code(runtime.block_on(run_buzz_mcp_stdio()));
    }
    let command = command.expect("non-MCP invocation parsed a Carl command");
    if let Command::Acp(args) = command {
        return exit_code(runtime.block_on(run_acp_stdio(args)));
    }
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

    exit_code(result.exit_classification())
}

fn exit_code(classification: ExitClassification) -> ExitCode {
    ExitCode::from(match classification {
        ExitClassification::Success => 0,
        ExitClassification::Failure => 1,
        ExitClassification::Cancelled => 130,
    })
}
