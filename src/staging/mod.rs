//! Sanitized, disposable workspaces for external coding agents.
//!
//! A stage is built from held directory capabilities, contains only bounded
//! regular UTF-8 files, and is deleted when its guard is dropped.

mod builder;
mod proposal;

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use cap_std::fs::PermissionsExt;
use cap_std::fs::{Dir, Permissions};
use uuid::Uuid;

use crate::artifacts::ArtifactId;
use crate::policy::Sha256Digest;
use crate::security::SecretRule;
use crate::sidecar::{ExecutionWorkspace, SidecarError, SidecarErrorCode};

use self::builder::{entry_is_link_or_reparse, link_count, open_directory_nofollow, same_file};

pub use builder::SanitizedStageBuilder;
pub use proposal::{
    ExactReplacementProposal, ProposalError, ProposalErrorCode, ProposalLimits, ProposalOutcome,
};

const MAX_CLEANUP_ENTRIES: usize = 100_000;
const MAX_AGGREGATE_PATH_BYTES: usize = 8 * 1024 * 1024;

fn account_path_bytes(total: &mut usize, path: &str) -> Result<(), ()> {
    let next = total.checked_add(path.len()).ok_or(())?;
    if next > MAX_AGGREGATE_PATH_BYTES {
        return Err(());
    }
    *total = next;
    Ok(())
}

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
    Artifact,
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
            StageErrorCode::Artifact => {
                formatter.write_str("The sealed baseline could not be persisted safely.")
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

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, StageError> {
        canonical_manifest_bytes(&self.entries)
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
    work_root: Option<Dir>,
    directory_name: String,
    containment: StageContainment,
    manifest: StageManifest,
    baseline: SealedBaseline,
    exclusions: Vec<StageExclusion>,
}

impl SanitizedStage {
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
    pub const fn baseline_manifest(&self) -> &StageManifest {
        self.baseline.manifest()
    }

    #[must_use]
    pub const fn sealed_baseline(&self) -> &SealedBaseline {
        &self.baseline
    }

    #[must_use]
    pub fn exclusions(&self) -> &[StageExclusion] {
        &self.exclusions
    }

    pub fn execution_workspace(&self) -> Result<ExecutionWorkspace, SidecarError> {
        let work_root = self
            .work_root
            .as_ref()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::InvalidConfiguration))?;
        ExecutionWorkspace::open_matching_held(&self.path, work_root)
    }

    /// Remove the disposable stage immediately, returning a sanitized error if
    /// filesystem metadata prevents bounded cleanup.
    pub fn cleanup(mut self) -> Result<(), StageError> {
        self.cleanup_inner()
            .map_err(|_| StageError::new(StageErrorCode::Io))
    }

    fn cleanup_inner(&mut self) -> io::Result<()> {
        let Some(work_root) = self.work_root.as_ref() else {
            return Ok(());
        };
        let held_metadata = work_root.dir_metadata()?;
        let held_name = matching_held_directory_name(&self.parent, &self.directory_name, work_root);
        let mut cleanup_error = held_name.as_ref().err().map(clone_io_error);
        let held_name = held_name.ok().flatten();
        let mut quarantine_name = held_name.as_ref().and_then(|held_name| {
            match quarantine_held_directory(&self.parent, held_name, &held_metadata) {
                Ok(name) => Some(name),
                Err(error) => {
                    if cleanup_error.is_none() {
                        cleanup_error = Some(error);
                    }
                    None
                }
            }
        });

        if let Err(error) = scrub_cleanup_tree(work_root)
            && cleanup_error.is_none()
        {
            cleanup_error = Some(error);
        }
        drop(self.work_root.take());

        if quarantine_name.is_none()
            && let Some(held_name) = held_name.as_ref()
            && let Ok(name) = quarantine_held_directory(&self.parent, held_name, &held_metadata)
        {
            quarantine_name = Some(name);
        }
        if let Some(quarantine_name) = quarantine_name {
            return match self.parent.remove_dir(&quarantine_name) {
                Ok(()) => Ok(()),
                Err(remove_error) => Err(cleanup_error.unwrap_or(remove_error)),
            };
        }
        if held_name.is_none() && cleanup_error.is_none() {
            cleanup_error = Some(io::Error::new(
                io::ErrorKind::NotFound,
                "the held disposable stage moved outside its parent",
            ));
        }
        Err(cleanup_error
            .unwrap_or_else(|| io::Error::other("the disposable stage could not be isolated")))
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
        if self.cleanup_inner().is_err() {
            eprintln!("Carl could not completely remove a disposable agent stage.");
        }
    }
}

fn scrub_cleanup_tree(root: &Dir) -> io::Result<()> {
    let mut entries_seen = 0_usize;
    let mut pending_directories = VecDeque::new();
    scrub_cleanup_directory(
        root,
        root,
        true,
        &mut pending_directories,
        &mut entries_seen,
    )?;

    while let Some(name) = pending_directories.pop_front() {
        let directory = open_directory_nofollow(root, &name)?;
        scrub_cleanup_directory(
            &directory,
            root,
            false,
            &mut pending_directories,
            &mut entries_seen,
        )?;
        drop(directory);
        root.remove_dir(&name)?;
    }
    Ok(())
}

fn scrub_cleanup_directory(
    directory: &Dir,
    root: &Dir,
    is_root: bool,
    pending_directories: &mut VecDeque<OsString>,
    entries_seen: &mut usize,
) -> io::Result<()> {
    let mut directory_permissions = directory.dir_metadata()?.permissions();
    make_cleanup_directory_permissions(&mut directory_permissions);
    directory.set_permissions(".", directory_permissions)?;

    let entries = directory.entries()?;
    for entry in entries {
        let entry = entry?;
        *entries_seen = entries_seen
            .checked_add(1)
            .ok_or_else(|| io::Error::other("disposable stage cleanup limit exceeded"))?;
        if *entries_seen > MAX_CLEANUP_ENTRIES {
            return Err(io::Error::other("disposable stage cleanup limit exceeded"));
        }

        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if entry_is_link_or_reparse(&entry, &file_type)? {
            if file_type.is_dir() {
                directory.remove_dir(&name)?;
            } else {
                directory.remove_file(&name)?;
            }
            continue;
        }

        let metadata = entry.metadata()?;
        let mut permissions = metadata.permissions();
        if file_type.is_dir() {
            make_cleanup_directory_permissions(&mut permissions);
            directory.set_permissions(&name, permissions)?;
            if is_root {
                pending_directories.push_back(name);
            } else {
                let flattened_name =
                    OsString::from(format!(".carl-cleanup-node-{}", Uuid::new_v4()));
                directory.rename(&name, root, &flattened_name)?;
                pending_directories.push_back(flattened_name);
            }
        } else {
            if file_type.is_file() && link_count(&metadata) == Some(1) {
                make_cleanup_file_permissions(&mut permissions);
                directory.set_permissions(&name, permissions)?;
            }
            directory.remove_file(&name)?;
        }
    }
    Ok(())
}

fn quarantine_held_directory(
    parent: &Dir,
    held_name: &OsString,
    held_metadata: &cap_std::fs::Metadata,
) -> io::Result<String> {
    let quarantine_name = format!(".carl-cleanup-{}", Uuid::new_v4());
    parent.rename(held_name, parent, &quarantine_name)?;
    let candidate = open_directory_nofollow(parent, &quarantine_name)?;
    if same_file(held_metadata, &candidate.dir_metadata()?) {
        Ok(quarantine_name)
    } else {
        drop(candidate);
        let _ = parent.rename(&quarantine_name, parent, held_name);
        Err(io::Error::other(
            "the disposable stage changed identity while being isolated",
        ))
    }
}

fn matching_held_directory_name(
    parent: &Dir,
    preferred_name: &str,
    held: &Dir,
) -> io::Result<Option<OsString>> {
    let held_metadata = held.dir_metadata()?;
    if let Ok(candidate) = open_directory_nofollow(parent, preferred_name)
        && same_file(&held_metadata, &candidate.dir_metadata()?)
    {
        return Ok(Some(OsString::from(preferred_name)));
    }

    let mut entries_seen = 0_usize;
    let entries = parent.entries()?;
    for entry in entries {
        let entry = entry?;
        entries_seen = entries_seen
            .checked_add(1)
            .ok_or_else(|| io::Error::other("stage-parent scan limit exceeded"))?;
        if entries_seen > MAX_CLEANUP_ENTRIES {
            return Err(io::Error::other("stage-parent scan limit exceeded"));
        }
        let name = entry.file_name();
        if name == preferred_name {
            continue;
        }
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || entry_is_link_or_reparse(&entry, &file_type)? {
            continue;
        }
        let candidate = open_directory_nofollow(parent, &name)?;
        if same_file(&held_metadata, &candidate.dir_metadata()?) {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

fn clone_io_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

#[cfg(unix)]
fn make_cleanup_directory_permissions(permissions: &mut Permissions) {
    permissions.set_mode(0o700);
}

#[cfg(not(unix))]
fn make_cleanup_directory_permissions(permissions: &mut Permissions) {
    permissions.set_readonly(false);
}

#[cfg(unix)]
fn make_cleanup_file_permissions(permissions: &mut Permissions) {
    permissions.set_mode(0o600);
}

#[cfg(not(unix))]
fn make_cleanup_file_permissions(permissions: &mut Permissions) {
    permissions.set_readonly(false);
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealedBaseline {
    manifest: StageManifest,
    manifest_artifact_id: ArtifactId,
    source_preconditions_artifact_id: ArtifactId,
    source_preconditions_digest: Sha256Digest,
    entries: Vec<SealedBaselineEntry>,
    directories: Vec<String>,
}

impl SealedBaseline {
    pub(crate) fn new(
        manifest: StageManifest,
        manifest_artifact_id: ArtifactId,
        source_preconditions_artifact_id: ArtifactId,
        source_preconditions_digest: Sha256Digest,
        entries: Vec<SealedBaselineEntry>,
        directories: Vec<String>,
    ) -> Self {
        Self {
            manifest,
            manifest_artifact_id,
            source_preconditions_artifact_id,
            source_preconditions_digest,
            entries,
            directories,
        }
    }

    #[must_use]
    pub const fn manifest(&self) -> &StageManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn manifest_artifact_id(&self) -> &ArtifactId {
        &self.manifest_artifact_id
    }

    #[must_use]
    pub const fn source_preconditions_artifact_id(&self) -> &ArtifactId {
        &self.source_preconditions_artifact_id
    }

    #[must_use]
    pub const fn source_preconditions_digest(&self) -> Sha256Digest {
        self.source_preconditions_digest
    }

    #[must_use]
    pub fn entries(&self) -> &[SealedBaselineEntry] {
        &self.entries
    }

    pub(crate) fn directories(&self) -> &[String] {
        &self.directories
    }
}

impl fmt::Debug for SealedBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedBaseline")
            .field("manifest", &self.manifest)
            .field("manifest_artifact_id", &self.manifest_artifact_id)
            .field(
                "source_preconditions_artifact_id",
                &self.source_preconditions_artifact_id,
            )
            .field(
                "source_preconditions_digest",
                &self.source_preconditions_digest,
            )
            .field("entry_count", &self.entries.len())
            .field("directory_count", &self.directories.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealedBaselineEntry {
    path: String,
    bytes: u64,
    content_digest: Sha256Digest,
    content_artifact_id: ArtifactId,
    source_identity: SourceIdentity,
}

impl fmt::Debug for SealedBaselineEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedBaselineEntry")
            .field("path", &self.path)
            .field("bytes", &self.bytes)
            .field("content_digest", &self.content_digest)
            .field("content_artifact_id", &self.content_artifact_id)
            .field("source_identity", &"<redacted>")
            .finish()
    }
}

impl SealedBaselineEntry {
    pub(crate) fn new(
        path: String,
        bytes: u64,
        content_digest: Sha256Digest,
        content_artifact_id: ArtifactId,
        source_identity: SourceIdentity,
    ) -> Self {
        Self {
            path,
            bytes,
            content_digest,
            content_artifact_id,
            source_identity,
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

    #[must_use]
    pub const fn content_artifact_id(&self) -> &ArtifactId {
        &self.content_artifact_id
    }

    pub(crate) const fn source_identity(&self) -> &SourceIdentity {
        &self.source_identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceIdentity {
    pub(crate) platform: &'static str,
    pub(crate) identity_a: String,
    pub(crate) identity_b: String,
    pub(crate) owner_id: String,
    pub(crate) owner_mode: Option<u32>,
}

pub(crate) struct SourcePreconditionRef<'a> {
    pub(crate) path: &'a str,
    pub(crate) bytes: u64,
    pub(crate) content_digest: Sha256Digest,
    pub(crate) platform: &'a str,
    pub(crate) identity_a: &'a str,
    pub(crate) identity_b: &'a str,
    pub(crate) owner_id: &'a str,
    pub(crate) owner_mode: Option<u32>,
}

pub(crate) fn canonical_source_preconditions<'a>(
    manifest_digest: Sha256Digest,
    entries: impl ExactSizeIterator<Item = SourcePreconditionRef<'a>>,
) -> Result<Vec<u8>, StageError> {
    const DOMAIN: &[u8] = b"carl.source-preconditions.v1\0";

    fn append_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), StageError> {
        let value = value.as_bytes();
        let length = u32::try_from(value.len())
            .map_err(|_| StageError::new(StageErrorCode::InvalidEntry))?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value);
        Ok(())
    }

    let mut bytes = Vec::new();
    let mut aggregate_path_bytes = 0_usize;
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(manifest_digest.as_bytes());
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| StageError::new(StageErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for entry in entries {
        account_path_bytes(&mut aggregate_path_bytes, entry.path)
            .map_err(|()| StageError::new(StageErrorCode::LimitExceeded))?;
        append_text(&mut bytes, entry.path)?;
        bytes.extend_from_slice(&entry.bytes.to_be_bytes());
        bytes.extend_from_slice(entry.content_digest.as_bytes());
        let platform = match entry.platform {
            "unix" => 0_u8,
            "windows" => 1_u8,
            _ => return Err(StageError::new(StageErrorCode::InvalidEntry)),
        };
        bytes.push(platform);
        append_text(&mut bytes, entry.identity_a)?;
        append_text(&mut bytes, entry.identity_b)?;
        append_text(&mut bytes, entry.owner_id)?;
        match entry.owner_mode {
            Some(mode) if mode <= 0o7777 => {
                bytes.push(1);
                bytes.extend_from_slice(&mode.to_be_bytes());
            }
            None => bytes.push(0),
            Some(_) => return Err(StageError::new(StageErrorCode::InvalidEntry)),
        }
    }
    Ok(bytes)
}

pub(crate) fn canonical_manifest_bytes(
    entries: &[StageManifestEntry],
) -> Result<Vec<u8>, StageError> {
    let mut bytes = Vec::new();
    let mut aggregate_path_bytes = 0_usize;
    for entry in entries {
        let path = entry.path().as_bytes();
        account_path_bytes(&mut aggregate_path_bytes, entry.path())
            .map_err(|()| StageError::new(StageErrorCode::LimitExceeded))?;
        let path_len =
            u32::try_from(path.len()).map_err(|_| StageError::new(StageErrorCode::InvalidEntry))?;
        bytes.extend_from_slice(&path_len.to_be_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&entry.bytes().to_be_bytes());
        bytes.extend_from_slice(entry.content_digest().as_bytes());
        let stage_file = Path::new(entry.path());
        if stage_file.is_absolute()
            || stage_file
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(StageError::new(StageErrorCode::InvalidEntry));
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod path_budget_tests {
    use super::{MAX_AGGREGATE_PATH_BYTES, account_path_bytes};

    #[test]
    fn aggregate_path_budget_accepts_its_boundary_and_rejects_the_next_byte() {
        let mut total = MAX_AGGREGATE_PATH_BYTES - 1;
        account_path_bytes(&mut total, "x").expect("the exact path budget boundary is valid");
        assert_eq!(total, MAX_AGGREGATE_PATH_BYTES);
        assert!(
            account_path_bytes(&mut total, "x").is_err(),
            "aggregate path metadata must remain bounded"
        );
        assert_eq!(
            total, MAX_AGGREGATE_PATH_BYTES,
            "a rejected path must not consume budget"
        );
    }
}
