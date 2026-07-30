//! Sanitized, disposable workspaces for external coding agents.
//!
//! A stage is built from held directory capabilities, contains only bounded
//! regular UTF-8 files, and is deleted when its guard is dropped.

mod builder;

use std::fmt;
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;

use crate::policy::Sha256Digest;
use crate::security::SecretRule;
use crate::sidecar::{ExecutionWorkspace, SidecarError};

pub use builder::SanitizedStageBuilder;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageContainment {
    CurrentUserPrivateVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageErrorCode {
    InvalidRoot,
    InvalidLimits,
    InvalidEntry,
    LimitExceeded,
    SecretDetected,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageExclusionReason {
    ProtectedPath,
    SensitiveFilename,
    CompatibilityInstruction,
    NonUtf8,
    HardLink,
    Symlink,
    SpecialFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl StageLimits {
    const MAX_FILES: usize = 100_000;
    const MAX_FILE_BYTES: u64 = 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

    pub fn new(
        max_files: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
    ) -> Result<Self, StageError> {
        if max_files == 0
            || max_file_bytes == 0
            || max_total_bytes == 0
            || max_files > Self::MAX_FILES
            || max_file_bytes > Self::MAX_FILE_BYTES
            || max_total_bytes > Self::MAX_TOTAL_BYTES
            || max_file_bytes > max_total_bytes
        {
            return Err(StageError::new(StageErrorCode::InvalidLimits));
        }
        Ok(Self {
            max_files,
            max_file_bytes,
            max_total_bytes,
        })
    }

    pub(crate) const fn max_files(self) -> usize {
        self.max_files
    }

    pub(crate) const fn max_file_bytes(self) -> u64 {
        self.max_file_bytes
    }

    pub(crate) const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StageError {
    code: StageErrorCode,
    path: Option<String>,
    secret_rule: Option<SecretRule>,
}

impl StageError {
    pub(crate) const fn new(code: StageErrorCode) -> Self {
        Self {
            code,
            path: None,
            secret_rule: None,
        }
    }

    pub(crate) fn at(code: StageErrorCode, path: String) -> Self {
        Self {
            code,
            path: Some(path),
            secret_rule: None,
        }
    }

    pub(crate) fn secret(path: String, rule: SecretRule) -> Self {
        Self {
            code: StageErrorCode::SecretDetected,
            path: Some(path),
            secret_rule: Some(rule),
        }
    }

    #[must_use]
    pub const fn code(&self) -> StageErrorCode {
        self.code
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    #[must_use]
    pub const fn secret_rule(&self) -> Option<SecretRule> {
        self.secret_rule
    }
}

impl fmt::Debug for StageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StageError")
            .field("code", &self.code)
            .field("path", &self.path)
            .field("secret_rule", &self.secret_rule)
            .finish()
    }
}

impl fmt::Display for StageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            StageErrorCode::InvalidRoot => {
                formatter.write_str("The source or stage root is not safe.")
            }
            StageErrorCode::InvalidLimits => {
                formatter.write_str("The requested stage limits are invalid.")
            }
            StageErrorCode::InvalidEntry => {
                formatter.write_str("A workspace entry changed or could not be represented safely.")
            }
            StageErrorCode::LimitExceeded => {
                formatter.write_str("The sanitized stage exceeded a configured limit.")
            }
            StageErrorCode::SecretDetected => {
                formatter.write_str("A source file contains high-confidence secret material.")
            }
            StageErrorCode::Io => formatter.write_str("The sanitized stage could not be prepared."),
        }
    }
}

impl std::error::Error for StageError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageManifestEntry {
    path: String,
    bytes: u64,
    content_digest: Sha256Digest,
}

impl StageManifestEntry {
    pub(crate) fn new(path: String, bytes: u64, content_digest: Sha256Digest) -> Self {
        Self {
            path,
            bytes,
            content_digest,
        }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    #[must_use]
    pub const fn content_digest(&self) -> Sha256Digest {
        self.content_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageManifest {
    digest: Sha256Digest,
    total_bytes: u64,
    entries: Vec<StageManifestEntry>,
}

impl StageManifest {
    pub(crate) fn new(
        digest: Sha256Digest,
        total_bytes: u64,
        entries: Vec<StageManifestEntry>,
    ) -> Self {
        Self {
            digest,
            total_bytes,
            entries,
        }
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn entries(&self) -> &[StageManifestEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageExclusion {
    path: String,
    reason: StageExclusionReason,
}

impl StageExclusion {
    pub(crate) fn new(path: String, reason: StageExclusionReason) -> Self {
        Self { path, reason }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn reason(&self) -> StageExclusionReason {
        self.reason
    }
}

pub struct SanitizedStage {
    path: PathBuf,
    parent: Dir,
    directory_name: String,
    containment: StageContainment,
    manifest: StageManifest,
    exclusions: Vec<StageExclusion>,
}

impl SanitizedStage {
    pub(crate) fn new(
        path: PathBuf,
        parent: Dir,
        directory_name: String,
        containment: StageContainment,
        manifest: StageManifest,
        exclusions: Vec<StageExclusion>,
    ) -> Self {
        Self {
            path,
            parent,
            directory_name,
            containment,
            manifest,
            exclusions,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn containment(&self) -> StageContainment {
        self.containment
    }

    #[must_use]
    pub const fn manifest(&self) -> &StageManifest {
        &self.manifest
    }

    #[must_use]
    pub fn exclusions(&self) -> &[StageExclusion] {
        &self.exclusions
    }

    pub fn execution_workspace(&self) -> Result<ExecutionWorkspace, SidecarError> {
        ExecutionWorkspace::open(&self.path)
    }
}

impl fmt::Debug for SanitizedStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedStage")
            .field("path", &"<opaque>")
            .field("containment", &self.containment)
            .field("manifest", &self.manifest)
            .field("exclusions", &self.exclusions)
            .finish()
    }
}

impl Drop for SanitizedStage {
    fn drop(&mut self) {
        let _ = self.parent.remove_dir_all(&self.directory_name);
    }
}
