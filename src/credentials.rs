use std::fmt;
use std::path::Path;

use keyring::v1::Entry;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::providers::catalog::ProviderKind;
use crate::providers::http::SecretCredential;

const KEYRING_SERVICE: &str = "dev.carl-agent.credentials";
const PREFERENCE_FILE: &str = "provider.json";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialError {
    #[error("the operating-system credential vault is unavailable")]
    VaultUnavailable,
    #[error("the provider credential is unavailable")]
    CredentialUnavailable,
    #[error("the provider preference is invalid")]
    InvalidPreference,
}

pub struct CredentialVault;

impl CredentialVault {
    pub fn store(
        provider: ProviderKind,
        credential: SecretCredential,
    ) -> Result<(), CredentialError> {
        let entry = entry(provider)?;
        credential
            .with_bytes(|bytes| entry.set_secret(bytes))
            .map_err(|_| CredentialError::VaultUnavailable)
    }

    pub fn load(provider: ProviderKind) -> Result<SecretCredential, CredentialError> {
        let secret = entry(provider)?
            .get_secret()
            .map_err(|_| CredentialError::CredentialUnavailable)?;
        SecretCredential::new(secret).map_err(|_| CredentialError::CredentialUnavailable)
    }

    pub fn delete(provider: ProviderKind) -> Result<(), CredentialError> {
        entry(provider)?
            .delete_credential()
            .map_err(|_| CredentialError::CredentialUnavailable)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderPreference {
    provider: ProviderKind,
}

pub fn store_provider_preference(
    data_root: &Path,
    provider: ProviderKind,
) -> Result<(), CredentialError> {
    let encoded = serde_json::to_vec(&ProviderPreference { provider })
        .map_err(|_| CredentialError::InvalidPreference)?;
    let path = data_root.join(PREFERENCE_FILE);
    let temporary = data_root.join(format!(".provider-{}.tmp", Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    use std::io::Write as _;
    let mut file = options
        .open(&temporary)
        .map_err(|_| CredentialError::InvalidPreference)?;
    file.write_all(&encoded)
        .map_err(|_| CredentialError::InvalidPreference)?;
    file.sync_all()
        .map_err(|_| CredentialError::InvalidPreference)?;
    drop(file);
    std::fs::rename(temporary, path).map_err(|_| CredentialError::InvalidPreference)
}

pub fn load_provider_preference(data_root: &Path) -> Result<Option<ProviderKind>, CredentialError> {
    let path = data_root.join(PREFERENCE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| CredentialError::InvalidPreference)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 {
        return Err(CredentialError::InvalidPreference);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 {
            return Err(CredentialError::InvalidPreference);
        }
    }
    let bytes = std::fs::read(path).map_err(|_| CredentialError::InvalidPreference)?;
    let preference: ProviderPreference =
        serde_json::from_slice(&bytes).map_err(|_| CredentialError::InvalidPreference)?;
    Ok(Some(preference.provider))
}

fn entry(provider: ProviderKind) -> Result<Entry, CredentialError> {
    Entry::new(KEYRING_SERVICE, provider_account(provider))
        .map_err(|_| CredentialError::VaultUnavailable)
}

const fn provider_account(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::OpenAiApi => "openai-api",
        ProviderKind::OpenRouter => "openrouter",
        ProviderKind::OpenAiSubscription => "openai-subscription",
    }
}

impl fmt::Debug for CredentialVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialVault(<os-managed>)")
    }
}
