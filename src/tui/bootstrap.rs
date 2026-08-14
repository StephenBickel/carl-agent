use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::process::{Child, Command};

use crate::service::client::{ServiceClientErrorCode, TaskServiceClient};
use crate::sidecar::{canonical_private_data_root, prepare_default_data_root};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BootstrapError {
    #[error("the Carl data directory or workspace is invalid")]
    InvalidConfiguration,
    #[error("the Carl service endpoint identity is invalid")]
    InvalidEndpoint,
    #[error("the Carl service could not be launched")]
    LaunchFailed,
    #[error("the Carl service did not become ready")]
    ReadinessTimedOut,
}

pub fn service_launch_environment(
    ambient: &BTreeMap<OsString, OsString>,
    data_root: &Path,
) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    for name in [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "TMPDIR",
        "TEMP",
        "TMP",
        "CARL_CODEX_EXECUTABLE",
    ] {
        if let Some(value) = ambient.get(&OsString::from(name)) {
            environment.insert(OsString::from(name), value.clone());
        }
    }
    environment.insert(
        OsString::from("CARL_DATA_DIR"),
        data_root.as_os_str().to_owned(),
    );
    environment
}

#[must_use]
pub const fn should_launch_service(code: ServiceClientErrorCode) -> bool {
    matches!(code, ServiceClientErrorCode::Unavailable)
}

pub fn resolve_or_create_data_root(
    ambient: &BTreeMap<OsString, OsString>,
) -> Result<PathBuf, BootstrapError> {
    if let Some(configured) = ambient.get(&OsString::from("CARL_DATA_DIR")) {
        return canonical_private_data_root(&PathBuf::from(configured))
            .map_err(|_| BootstrapError::InvalidConfiguration);
    }

    let home_variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = ambient
        .get(&OsString::from(home_variable))
        .map(PathBuf::from)
        .ok_or(BootstrapError::InvalidConfiguration)?;
    let home = canonical_directory(&home)?;
    prepare_default_data_root(&home.join(".carl")).map_err(|_| BootstrapError::InvalidConfiguration)
}

pub async fn connect_or_launch(
    data_root: impl AsRef<Path>,
    workspace: impl AsRef<Path>,
) -> Result<TaskServiceClient, BootstrapError> {
    let data_root = canonical_directory(data_root.as_ref())?;
    let workspace = canonical_directory(workspace.as_ref())?;
    match TaskServiceClient::connect(&data_root).await {
        Ok(client) => return Ok(client),
        Err(error) if should_launch_service(error.code()) => {}
        Err(error) if error.code() == ServiceClientErrorCode::InvalidEndpoint => {
            return Err(BootstrapError::InvalidEndpoint);
        }
        Err(_) => return Err(BootstrapError::LaunchFailed),
    }

    let executable = env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| BootstrapError::LaunchFailed)?;
    let ambient = env::vars_os().collect::<BTreeMap<_, _>>();
    let mut command = Command::new(executable);
    command
        .arg("serve")
        .current_dir(&workspace)
        .env_clear()
        .envs(service_launch_environment(&ambient, &data_root))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    let mut child = command.spawn().map_err(|_| BootstrapError::LaunchFailed)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TaskServiceClient::connect(&data_root).await {
            Ok(client) => {
                reap_in_background(child);
                return Ok(client);
            }
            Err(error) if error.code() == ServiceClientErrorCode::InvalidEndpoint => {
                reap_in_background(child);
                return Err(BootstrapError::InvalidEndpoint);
            }
            Err(_) => {}
        }
        if child
            .try_wait()
            .map_err(|_| BootstrapError::LaunchFailed)?
            .is_some()
        {
            return Err(BootstrapError::LaunchFailed);
        }
        if tokio::time::Instant::now() >= deadline {
            reap_in_background(child);
            return Err(BootstrapError::ReadinessTimedOut);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, BootstrapError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| BootstrapError::InvalidConfiguration)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BootstrapError::InvalidConfiguration);
    }
    std::fs::canonicalize(path).map_err(|_| BootstrapError::InvalidConfiguration)
}

fn reap_in_background(mut child: Child) {
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
}
