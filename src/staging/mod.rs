//! Sanitized, disposable workspaces for external coding agents.
//!
//! A stage is built from held directory capabilities, contains only bounded
//! regular UTF-8 files, and is deleted when its guard is dropped.

mod builder;
mod proposal;

use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::PermissionsExt;
use cap_std::fs::{Dir, Permissions};
use uuid::Uuid;

use crate::artifacts::ArtifactId;
use crate::policy::Sha256Digest;
use crate::security::SecretRule;
use crate::sidecar::{ExecutionWorkspace, SidecarError, SidecarErrorCode};

use self::builder::{
    create_private_directory, create_private_file, entry_is_link_or_reparse,
    held_private_directory_is_verified, link_count, named_path_matches_held,
    open_directory_nofollow, root_is_link_or_reparse, same_file, secure_created_file,
};

pub use builder::SanitizedStageBuilder;
pub(crate) use proposal::canonical_proposal_envelope;
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

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CandidateFile {
    pub(crate) path: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct VerificationCandidate {
    path: PathBuf,
    parent: Dir,
    work_root: Option<Dir>,
    directory_name: String,
}

impl VerificationCandidate {
    pub(crate) fn reconstruct(
        parent_path: &Path,
        directories: &[String],
        files: &[CandidateFile],
    ) -> Result<Self, StageError> {
        let (parent_path, parent) = open_private_parent(parent_path)?;
        validate_candidate_topology(directories, files)?;

        let directory_name = format!("verify-{}", Uuid::new_v4());
        let path = parent_path.join(&directory_name);
        let work_root = match create_private_directory(&parent, &directory_name) {
            Ok(work_root) => work_root,
            Err(_) => {
                let _ = parent.remove_dir_all(&directory_name);
                return Err(StageError::new(StageErrorCode::Io));
            }
        };

        let reconstruct = || -> Result<(), StageError> {
            let mut ordered_directories = directories.to_vec();
            ordered_directories.sort_by(|left, right| {
                path_depth(left)
                    .cmp(&path_depth(right))
                    .then_with(|| left.cmp(right))
            });
            for relative in &ordered_directories {
                let (parent_relative, name) = split_relative_path(relative)?;
                let held_parent = open_relative_directory(&work_root, parent_relative)?;
                create_private_directory(&held_parent, name)
                    .map_err(|_| StageError::at(StageErrorCode::Io, relative.clone()))?;
            }

            for candidate_file in files {
                let (parent_relative, name) = split_relative_path(&candidate_file.path)?;
                let held_parent = open_relative_directory(&work_root, parent_relative)?;
                let mut file = create_private_file(&held_parent, name)
                    .map_err(|_| StageError::at(StageErrorCode::Io, candidate_file.path.clone()))?;
                file.write_all(&candidate_file.bytes)
                    .map_err(|_| StageError::at(StageErrorCode::Io, candidate_file.path.clone()))?;
                file.sync_all()
                    .map_err(|_| StageError::at(StageErrorCode::Io, candidate_file.path.clone()))?;
                secure_created_file(&file)
                    .map_err(|_| StageError::at(StageErrorCode::Io, candidate_file.path.clone()))?;
            }
            Ok(())
        };

        if let Err(error) = reconstruct() {
            let mut candidate = Self {
                path,
                parent,
                work_root: Some(work_root),
                directory_name,
            };
            let _ = candidate.cleanup_inner();
            return Err(error);
        }

        if !named_path_matches_held(&path, &work_root)
            || !held_private_directory_is_verified(&work_root)
            || !named_path_matches_held(&parent_path, &parent)
        {
            let mut candidate = Self {
                path,
                parent,
                work_root: Some(work_root),
                directory_name,
            };
            let _ = candidate.cleanup_inner();
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        Ok(Self {
            path,
            parent,
            work_root: Some(work_root),
            directory_name,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn execution_workspace(&self) -> Result<ExecutionWorkspace, SidecarError> {
        let work_root = self
            .work_root
            .as_ref()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::InvalidConfiguration))?;
        ExecutionWorkspace::open_matching_held(&self.path, work_root)
    }

    pub(crate) fn held_root(&self) -> Result<&Dir, StageError> {
        self.work_root
            .as_ref()
            .ok_or_else(|| StageError::new(StageErrorCode::InvalidRoot))
    }

    pub(crate) fn inspect(
        &self,
        expected_entries: &[StageManifestEntry],
        expected_directories: &[String],
        limits: ProposalLimits,
        secret_filter: crate::security::SecretFilter,
    ) -> Result<proposal::CandidateSnapshotSeal, ProposalError> {
        proposal::inspect_verification_candidate(
            self.held_root()
                .map_err(|_| ProposalError::from_stage_io())?,
            expected_entries,
            expected_directories,
            limits,
            secret_filter,
        )
    }

    pub(crate) fn cleanup(mut self) -> Result<(), StageError> {
        self.cleanup_inner()
            .map_err(|_| StageError::new(StageErrorCode::Io))
    }

    fn cleanup_inner(&mut self) -> io::Result<()> {
        cleanup_disposable_directory(&self.parent, &mut self.work_root, &self.directory_name)
    }
}

impl Drop for VerificationCandidate {
    fn drop(&mut self) {
        if self.cleanup_inner().is_err() {
            eprintln!("Carl could not completely remove a verification workspace.");
        }
    }
}

fn open_private_parent(parent_path: &Path) -> Result<(PathBuf, Dir), StageError> {
    if !parent_path.is_absolute() {
        return Err(StageError::new(StageErrorCode::InvalidRoot));
    }
    let metadata = std::fs::symlink_metadata(parent_path)
        .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
    if !metadata.is_dir() || root_is_link_or_reparse(&metadata) {
        return Err(StageError::new(StageErrorCode::InvalidRoot));
    }
    let canonical = std::fs::canonicalize(parent_path)
        .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
    let parent = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
    if !named_path_matches_held(&canonical, &parent) || !held_private_directory_is_verified(&parent)
    {
        return Err(StageError::new(StageErrorCode::InvalidRoot));
    }
    Ok((canonical, parent))
}

fn validate_candidate_topology(
    directories: &[String],
    files: &[CandidateFile],
) -> Result<(), StageError> {
    if directories.len().saturating_add(files.len()) > MAX_CLEANUP_ENTRIES {
        return Err(StageError::new(StageErrorCode::LimitExceeded));
    }

    let mut path_bytes = 0_usize;
    let mut directory_set = BTreeSet::new();
    for directory in directories {
        validate_relative_path(directory)?;
        account_path_bytes(&mut path_bytes, directory)
            .map_err(|()| StageError::new(StageErrorCode::LimitExceeded))?;
        if !directory_set.insert(directory.as_str()) {
            return Err(StageError::at(
                StageErrorCode::InvalidEntry,
                directory.clone(),
            ));
        }
        let (parent, _) = split_relative_path(directory)?;
        if !parent.is_empty() && !directory_set.contains(parent) {
            return Err(StageError::at(
                StageErrorCode::InvalidEntry,
                directory.clone(),
            ));
        }
    }

    let mut file_set = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for file in files {
        validate_relative_path(&file.path)?;
        account_path_bytes(&mut path_bytes, &file.path)
            .map_err(|()| StageError::new(StageErrorCode::LimitExceeded))?;
        if !file_set.insert(file.path.as_str()) || directory_set.contains(file.path.as_str()) {
            return Err(StageError::at(
                StageErrorCode::InvalidEntry,
                file.path.clone(),
            ));
        }
        let (parent, _) = split_relative_path(&file.path)?;
        if !parent.is_empty() && !directory_set.contains(parent) {
            return Err(StageError::at(
                StageErrorCode::InvalidEntry,
                file.path.clone(),
            ));
        }
        let bytes = u64::try_from(file.bytes.len())
            .map_err(|_| StageError::new(StageErrorCode::LimitExceeded))?;
        if bytes > 1024 * 1024 {
            return Err(StageError::at(
                StageErrorCode::LimitExceeded,
                file.path.clone(),
            ));
        }
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| StageError::new(StageErrorCode::LimitExceeded))?;
        if total_bytes > 100 * 1024 * 1024 {
            return Err(StageError::new(StageErrorCode::LimitExceeded));
        }
    }
    Ok(())
}

fn validate_relative_path(relative: &str) -> Result<(), StageError> {
    if relative.is_empty()
        || relative.len() > 4_096
        || Path::new(relative).is_absolute()
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(StageError::at(
            StageErrorCode::InvalidEntry,
            relative.to_owned(),
        ));
    }
    Ok(())
}

fn split_relative_path(relative: &str) -> Result<(&str, &str), StageError> {
    validate_relative_path(relative)?;
    Ok(relative
        .rsplit_once('/')
        .map_or(("", relative), |(parent, name)| (parent, name)))
}

fn path_depth(relative: &str) -> usize {
    relative.bytes().filter(|byte| *byte == b'/').count()
}

fn open_relative_directory(root: &Dir, relative: &str) -> Result<Dir, StageError> {
    let mut current = root
        .try_clone()
        .map_err(|_| StageError::new(StageErrorCode::Io))?;
    if relative.is_empty() {
        return Ok(current);
    }
    for component in relative.split('/') {
        current = open_directory_nofollow(&current, component)
            .map_err(|_| StageError::at(StageErrorCode::InvalidEntry, relative.to_owned()))?;
    }
    Ok(current)
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
        cleanup_disposable_directory(&self.parent, &mut self.work_root, &self.directory_name)
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

fn cleanup_disposable_directory(
    parent: &Dir,
    work_root: &mut Option<Dir>,
    directory_name: &str,
) -> io::Result<()> {
    let Some(held_root) = work_root.as_ref() else {
        return Ok(());
    };
    let held_metadata = held_root.dir_metadata()?;
    let held_name = matching_held_directory_name(parent, directory_name, held_root);
    let mut cleanup_error = held_name.as_ref().err().map(clone_io_error);
    let held_name = held_name.ok().flatten();
    let mut quarantine_name = held_name.as_ref().and_then(|held_name| {
        match quarantine_held_directory(parent, held_name, &held_metadata) {
            Ok(name) => Some(name),
            Err(error) => {
                if cleanup_error.is_none() {
                    cleanup_error = Some(error);
                }
                None
            }
        }
    });

    if let Err(error) = scrub_cleanup_tree(held_root)
        && cleanup_error.is_none()
    {
        cleanup_error = Some(error);
    }
    drop(work_root.take());

    if quarantine_name.is_none()
        && let Some(held_name) = held_name.as_ref()
        && let Ok(name) = quarantine_held_directory(parent, held_name, &held_metadata)
    {
        quarantine_name = Some(name);
    }
    if let Some(quarantine_name) = quarantine_name {
        return match parent.remove_dir(&quarantine_name) {
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

#[cfg(all(test, unix))]
mod verification_candidate_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{CandidateFile, ProposalLimits, StageManifestEntry, VerificationCandidate};
    use crate::policy::Sha256Digest;
    use crate::security::SecretFilter;

    #[test]
    fn fresh_candidate_preserves_sealed_empty_directories() {
        let root =
            PathBuf::from("/tmp").join(format!("carl-verification-candidate-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("secure fixture root");
        let directories = vec!["src".to_owned(), "src/empty".to_owned()];
        let files = vec![CandidateFile {
            path: "src/file.txt".to_owned(),
            bytes: b"sealed candidate".to_vec(),
        }];

        let candidate = VerificationCandidate::reconstruct(&root, &directories, &files)
            .expect("reconstruct candidate");
        assert_eq!(
            fs::read(candidate.path().join("src/file.txt")).expect("read candidate"),
            b"sealed candidate"
        );
        assert!(candidate.path().join("src/empty").is_dir());
        let candidate_path = candidate.path().to_path_buf();
        candidate.cleanup().expect("clean candidate");
        assert!(!candidate_path.exists());
        fs::remove_dir(root).expect("remove fixture root");
    }

    #[test]
    fn candidate_seal_detects_same_content_file_replacement() {
        let root = PathBuf::from("/tmp").join(format!("carl-verification-seal-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("secure fixture root");
        let contents = b"sealed candidate";
        let digest = Sha256Digest::from_bytes(Sha256::digest(contents).into());
        let expected = vec![StageManifestEntry::new(
            "src/file.txt".to_owned(),
            contents.len() as u64,
            digest,
        )];
        let expected_manifest_digest =
            super::builder::build_manifest(contents.len() as u64, expected.clone())
                .expect("expected manifest")
                .digest();
        let directories = vec!["src".to_owned()];
        let candidate = VerificationCandidate::reconstruct(
            &root,
            &directories,
            &[CandidateFile {
                path: "src/file.txt".to_owned(),
                bytes: contents.to_vec(),
            }],
        )
        .expect("reconstruct candidate");

        let before = candidate
            .inspect(
                &expected,
                &directories,
                ProposalLimits::new(1_024).expect("proposal limits"),
                SecretFilter,
            )
            .expect("seal before execution");
        let replacement = candidate.path().join("src/replacement.txt");
        fs::write(&replacement, contents).expect("write replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
            .expect("secure replacement");
        fs::rename(&replacement, candidate.path().join("src/file.txt"))
            .expect("replace candidate file");
        let after = candidate
            .inspect(
                &expected,
                &directories,
                ProposalLimits::new(1_024).expect("proposal limits"),
                SecretFilter,
            )
            .expect("seal after replacement");

        assert!(before.matches_expected_manifest(
            expected_manifest_digest,
            before.directory_manifest_digest(),
        ));
        assert!(!before.same_persistent_snapshot(&after));
        candidate.cleanup().expect("clean candidate");
        fs::remove_dir(root).expect("remove fixture root");
    }
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
