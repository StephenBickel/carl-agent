use std::fmt;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
use cap_primitives::fs::_WindowsByHandle;
use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt;
#[cfg(windows)]
use cap_std::fs::OpenOptionsExt;
use cap_std::fs::{Dir, Metadata, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{MetadataExt, Permissions, PermissionsExt};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::artifacts::ArtifactStore;
use crate::policy::Sha256Digest;
use crate::security::{SecretFilter, SecretRule};

use super::{
    SanitizedStage, SealedBaseline, SealedBaselineEntry, SourceIdentity, SourcePreconditionRef,
    StageContainment, StageError, StageErrorCode, StageExclusion, StageExclusionReason,
    StageLimits, StageManifest, StageManifestEntry, account_path_bytes, canonical_manifest_bytes,
    canonical_source_preconditions,
};

const MAX_DEPTH: usize = 64;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;

pub struct SanitizedStageBuilder {
    source_display_path: PathBuf,
    stage_parent_display_path: PathBuf,
    source: Dir,
    stage_parent: Dir,
    limits: StageLimits,
    secret_filter: SecretFilter,
}

impl SanitizedStageBuilder {
    pub fn open(
        source: &Path,
        stage_parent: &Path,
        limits: StageLimits,
        secret_filter: SecretFilter,
    ) -> Result<Self, StageError> {
        if !source.is_absolute() || !stage_parent.is_absolute() {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        let source_metadata = std::fs::symlink_metadata(source)
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        let parent_metadata = std::fs::symlink_metadata(stage_parent)
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        if !source_metadata.is_dir()
            || !parent_metadata.is_dir()
            || root_is_link_or_reparse(&source_metadata)
            || root_is_link_or_reparse(&parent_metadata)
        {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }
        if !private_parent_is_verified(stage_parent, &parent_metadata) {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        let source_path = std::fs::canonicalize(source)
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        let stage_parent_path = std::fs::canonicalize(stage_parent)
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        if source_path.starts_with(&stage_parent_path)
            || stage_parent_path.starts_with(&source_path)
            || crate::sidecar::directory_paths_overlap(&source_path, &stage_parent_path)
                .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?
            || root_contains_protected_component(&source_path)
            || root_contains_protected_component(&stage_parent_path)
        {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        let source = Dir::open_ambient_dir(&source_path, ambient_authority())
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        let stage_parent = Dir::open_ambient_dir(&stage_parent_path, ambient_authority())
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        if !named_path_matches_held(&source_path, &source)
            || !named_path_matches_held(&stage_parent_path, &stage_parent)
            || !held_private_directory_is_verified(&stage_parent)
        {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        Ok(Self {
            source_display_path: source_path,
            stage_parent_display_path: stage_parent_path,
            source,
            stage_parent,
            limits,
            secret_filter,
        })
    }

    pub fn prepare(self, artifacts: &ArtifactStore) -> Result<SanitizedStage, StageError> {
        if !named_path_matches_held(&self.source_display_path, &self.source)
            || !named_path_matches_held(&self.stage_parent_display_path, &self.stage_parent)
            || crate::sidecar::directory_paths_overlap(
                &self.source_display_path,
                &self.stage_parent_display_path,
            )
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?
            || artifacts
                .overlaps_canonical_path(&self.source_display_path)
                .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?
            || artifacts
                .overlaps_canonical_path(&self.stage_parent_display_path)
                .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?
        {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        let directory_name = format!("stage-{}", Uuid::new_v4());
        let stage_path = self.stage_parent_display_path.join(&directory_name);
        let destination = match create_private_directory(&self.stage_parent, &directory_name) {
            Ok(destination) => destination,
            Err(_) => {
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(StageError::new(StageErrorCode::Io));
            }
        };

        let mut state = BuildState::new(self.limits, self.secret_filter, artifacts);
        let walk_result = walk_directory(&self.source, &destination, "", 0, &mut state);
        if let Err(error) = walk_result {
            drop(destination);
            let _ = self.stage_parent.remove_dir_all(&directory_name);
            return Err(error);
        }
        if !named_path_matches_held(&self.source_display_path, &self.source)
            || !named_path_matches_held(&self.stage_parent_display_path, &self.stage_parent)
        {
            drop(destination);
            let _ = self.stage_parent.remove_dir_all(&directory_name);
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        state
            .entries
            .sort_by(|left, right| left.path().cmp(right.path()));
        state
            .baseline_entries
            .sort_by(|left, right| left.path().cmp(right.path()));
        state.directories.sort();
        state
            .exclusions
            .sort_by(|left, right| left.path().cmp(right.path()));
        let manifest = match build_manifest(state.total_bytes, state.entries) {
            Ok(manifest) => manifest,
            Err(error) => {
                drop(destination);
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(error);
            }
        };
        let manifest_bytes = match manifest.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                drop(destination);
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(error);
            }
        };
        let manifest_artifact = match artifacts.put(&manifest_bytes) {
            Ok(artifact) => artifact,
            Err(_) => {
                drop(destination);
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(StageError::new(StageErrorCode::Artifact));
            }
        };
        if manifest_artifact.id().as_str() != manifest.digest().to_string() {
            drop(destination);
            let _ = self.stage_parent.remove_dir_all(&directory_name);
            return Err(StageError::new(StageErrorCode::Artifact));
        }
        let source_preconditions = match canonical_source_preconditions(
            manifest.digest(),
            state.baseline_entries.iter().map(|entry| {
                let identity = entry.source_identity();
                SourcePreconditionRef {
                    path: entry.path(),
                    bytes: entry.bytes(),
                    content_digest: entry.content_digest(),
                    platform: identity.platform,
                    identity_a: &identity.identity_a,
                    identity_b: &identity.identity_b,
                    owner_id: &identity.owner_id,
                    owner_mode: identity.owner_mode,
                }
            }),
        ) {
            Ok(preconditions) => preconditions,
            Err(_) => {
                drop(destination);
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(StageError::new(StageErrorCode::Artifact));
            }
        };
        let source_preconditions_artifact = match artifacts.put(&source_preconditions) {
            Ok(artifact) => artifact,
            Err(_) => {
                drop(destination);
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(StageError::new(StageErrorCode::Artifact));
            }
        };
        let source_preconditions_digest =
            match Sha256Digest::parse(source_preconditions_artifact.id().as_str()) {
                Ok(digest) => digest,
                Err(_) => {
                    drop(destination);
                    let _ = self.stage_parent.remove_dir_all(&directory_name);
                    return Err(StageError::new(StageErrorCode::Artifact));
                }
            };
        let baseline = SealedBaseline::new(
            manifest.clone(),
            manifest_artifact.id().clone(),
            source_preconditions_artifact.id().clone(),
            source_preconditions_digest,
            state.baseline_entries,
            state.directories,
        );
        if !named_path_matches_held(&self.source_display_path, &self.source)
            || !named_path_matches_held(&self.stage_parent_display_path, &self.stage_parent)
        {
            drop(destination);
            let _ = self.stage_parent.remove_dir_all(&directory_name);
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }
        Ok(SanitizedStage {
            path: stage_path,
            parent: self.stage_parent,
            work_root: Some(destination),
            directory_name,
            containment: StageContainment::CurrentUserPrivateVerified,
            manifest,
            baseline,
            exclusions: state.exclusions,
        })
    }
}

impl fmt::Debug for SanitizedStageBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedStageBuilder")
            .field("source", &"<opaque>")
            .field("stage_parent", &"<opaque>")
            .field("limits", &self.limits)
            .finish()
    }
}

struct BuildState<'a> {
    limits: StageLimits,
    secret_filter: SecretFilter,
    artifacts: &'a ArtifactStore,
    entry_count: usize,
    path_bytes: usize,
    total_bytes: u64,
    entries: Vec<StageManifestEntry>,
    baseline_entries: Vec<SealedBaselineEntry>,
    directories: Vec<String>,
    exclusions: Vec<StageExclusion>,
}

impl<'a> BuildState<'a> {
    fn new(limits: StageLimits, secret_filter: SecretFilter, artifacts: &'a ArtifactStore) -> Self {
        Self {
            limits,
            secret_filter,
            artifacts,
            entry_count: 0,
            path_bytes: 0,
            total_bytes: 0,
            entries: Vec::new(),
            baseline_entries: Vec::new(),
            directories: Vec::new(),
            exclusions: Vec::new(),
        }
    }

    fn exclude(&mut self, path: String, reason: StageExclusionReason) {
        self.exclusions.push(StageExclusion::new(path, reason));
    }
}

fn walk_directory(
    source: &Dir,
    destination: &Dir,
    relative_parent: &str,
    depth: usize,
    state: &mut BuildState<'_>,
) -> Result<(), StageError> {
    if depth > MAX_DEPTH {
        return Err(StageError::at(
            StageErrorCode::LimitExceeded,
            relative_parent.to_owned(),
        ));
    }

    let remaining_entries = state.limits.max_files().saturating_sub(state.entry_count);
    let mut entries = source
        .entries()
        .map_err(|_| io_error(relative_parent))?
        .take(remaining_entries.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io_error(relative_parent))?;
    if entries.len() > remaining_entries {
        return Err(StageError::at(
            StageErrorCode::LimitExceeded,
            relative_parent.to_owned(),
        ));
    }
    state.entry_count = state
        .entry_count
        .checked_add(entries.len())
        .ok_or_else(|| StageError::at(StageErrorCode::LimitExceeded, relative_parent.to_owned()))?;
    entries.sort_by_key(cap_std::fs::DirEntry::file_name);

    for entry in entries {
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| StageError::at(StageErrorCode::InvalidEntry, relative_parent.into()))?;
        if name == "." || name == ".." || name.contains(['/', '\\']) {
            return Err(StageError::at(
                StageErrorCode::InvalidEntry,
                relative_parent.into(),
            ));
        }
        let relative = join_relative(relative_parent, name);
        if relative.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(StageError::at(StageErrorCode::LimitExceeded, relative));
        }
        account_path_bytes(&mut state.path_bytes, &relative)
            .map_err(|()| StageError::at(StageErrorCode::LimitExceeded, relative.clone()))?;
        let file_type = entry.file_type().map_err(|_| io_error(&relative))?;

        if entry_is_link_or_reparse(&entry, &file_type).map_err(|_| io_error(&relative))? {
            state.exclude(relative, StageExclusionReason::Symlink);
            continue;
        }
        if protected_directory(name) {
            state.exclude(relative, StageExclusionReason::ProtectedPath);
            continue;
        }
        if file_type.is_dir() {
            let source_child =
                open_directory_nofollow(source, name).map_err(|_| io_error(&relative))?;
            let destination_child =
                create_private_directory(destination, name).map_err(|_| io_error(&relative))?;
            state.directories.push(relative.clone());
            walk_directory(
                &source_child,
                &destination_child,
                &relative,
                depth + 1,
                state,
            )?;
            continue;
        }
        if !file_type.is_file() {
            state.exclude(relative, StageExclusionReason::SpecialFile);
            continue;
        }
        if let Some(reason) = excluded_file(&relative, name) {
            state.exclude(relative, reason);
            continue;
        }

        copy_regular_file(&entry, destination, name, relative, state)?;
    }
    Ok(())
}

fn copy_regular_file(
    entry: &cap_std::fs::DirEntry,
    destination: &Dir,
    name: &str,
    relative: String,
    state: &mut BuildState<'_>,
) -> Result<(), StageError> {
    let before = entry.metadata().map_err(|_| io_error(&relative))?;
    if matches!(pre_open_link_count(&before), Some(count) if count != 1) {
        state.exclude(relative, StageExclusionReason::HardLink);
        return Ok(());
    }
    if before.len() > state.limits.max_file_bytes() {
        return Err(StageError::at(StageErrorCode::LimitExceeded, relative));
    }
    if state.entries.len() >= state.limits.max_files() {
        return Err(StageError::at(StageErrorCode::LimitExceeded, relative));
    }
    let prospective_total = state
        .total_bytes
        .checked_add(before.len())
        .ok_or_else(|| StageError::at(StageErrorCode::LimitExceeded, relative.clone()))?;
    if prospective_total > state.limits.max_total_bytes() {
        return Err(StageError::at(StageErrorCode::LimitExceeded, relative));
    }

    let mut read_options = OpenOptions::new();
    read_options.read(true);
    set_no_follow(&mut read_options);
    let mut source_file = entry
        .open_with(&read_options)
        .map_err(|_| StageError::at(StageErrorCode::InvalidEntry, relative.clone()))?;
    let after = source_file
        .metadata()
        .map_err(|_| StageError::at(StageErrorCode::InvalidEntry, relative.clone()))?;
    if !opened_metadata_is_regular(&after)
        || !pre_open_matches_opened(&before, &after)
        || before.len() != after.len()
    {
        return Err(StageError::at(StageErrorCode::InvalidEntry, relative));
    }
    if link_count(&after) != Some(1) {
        state.exclude(relative, StageExclusionReason::HardLink);
        return Ok(());
    }

    let read_limit = state.limits.max_file_bytes().saturating_add(1);
    let mut contents = Vec::with_capacity(after.len() as usize);
    (&mut source_file)
        .take(read_limit)
        .read_to_end(&mut contents)
        .map_err(|_| io_error(&relative))?;
    if contents.len() as u64 != after.len() || contents.len() as u64 > state.limits.max_file_bytes()
    {
        return Err(StageError::at(StageErrorCode::InvalidEntry, relative));
    }
    let final_metadata = source_file
        .metadata()
        .map_err(|_| StageError::at(StageErrorCode::InvalidEntry, relative.clone()))?;
    let named_entry_matches = named_entry_matches(entry, &read_options, &final_metadata)
        .map_err(|_| StageError::at(StageErrorCode::InvalidEntry, relative.clone()))?;
    if !opened_metadata_is_regular(&final_metadata)
        || link_count(&final_metadata) != Some(1)
        || final_metadata.len() != after.len()
        || !same_file(&after, &final_metadata)
        || !named_entry_matches
    {
        return Err(StageError::at(StageErrorCode::InvalidEntry, relative));
    }
    if std::str::from_utf8(&contents).is_err() {
        state.exclude(relative, StageExclusionReason::NonUtf8);
        return Ok(());
    }
    if let Err(finding) = state.secret_filter.inspect(&contents) {
        if finding.rule() == SecretRule::NonUtf8 {
            state.exclude(relative, StageExclusionReason::NonUtf8);
            return Ok(());
        }
        return Err(StageError::secret(relative, finding.rule()));
    }

    let baseline_artifact = state
        .artifacts
        .put(&contents)
        .map_err(|_| StageError::at(StageErrorCode::Artifact, relative.clone()))?;
    let content_digest = Sha256Digest::from_bytes(Sha256::digest(&contents).into());
    if baseline_artifact.id().as_str() != content_digest.to_string() {
        return Err(StageError::at(StageErrorCode::Artifact, relative));
    }
    let identity = source_identity(&final_metadata)
        .ok_or_else(|| StageError::at(StageErrorCode::InvalidEntry, relative.clone()))?;

    let mut destination_file =
        create_private_file(destination, name).map_err(|_| io_error(&relative))?;
    destination_file
        .write_all(&contents)
        .map_err(|_| io_error(&relative))?;
    destination_file
        .sync_all()
        .map_err(|_| io_error(&relative))?;
    secure_created_file(&destination_file).map_err(|_| io_error(&relative))?;

    state.total_bytes = prospective_total;
    state.entries.push(StageManifestEntry::new(
        relative.clone(),
        contents.len() as u64,
        content_digest,
    ));
    state.baseline_entries.push(SealedBaselineEntry::new(
        relative,
        contents.len() as u64,
        content_digest,
        baseline_artifact.id().clone(),
        identity,
    ));
    Ok(())
}

pub(super) fn build_manifest(
    total_bytes: u64,
    entries: Vec<StageManifestEntry>,
) -> Result<StageManifest, StageError> {
    let canonical = canonical_manifest_bytes(&entries)?;
    let digest_bytes: [u8; 32] = Sha256::digest(canonical).into();
    let digest_text = digest_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let digest = Sha256Digest::parse(&digest_text)
        .map_err(|_| StageError::new(StageErrorCode::InvalidEntry))?;
    Ok(StageManifest::new(digest, total_bytes, entries))
}

pub(super) fn excluded_file(relative: &str, name: &str) -> Option<StageExclusionReason> {
    if relative == ".mcp.json" {
        return Some(StageExclusionReason::ProtectedPath);
    }
    if compatibility_instruction(relative, name) {
        return Some(StageExclusionReason::CompatibilityInstruction);
    }
    let lower = name.to_ascii_lowercase();
    if lower == ".env"
        || lower.starts_with(".env.")
        || ["pem", "key", "p12", "pfx", "crt", "cer"]
            .iter()
            .any(|extension| lower.ends_with(&format!(".{extension}")))
    {
        return Some(StageExclusionReason::SensitiveFilename);
    }
    None
}

fn compatibility_instruction(relative: &str, name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "agents.md" | "claude.md" | "gemini.md" | ".cursorrules"
    ) || relative.eq_ignore_ascii_case(".github/copilot-instructions.md")
}

pub(super) fn protected_directory(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git"
            | ".carl"
            | ".codex"
            | ".grok"
            | ".xai"
            | ".openai"
            | ".claude"
            | ".cursor"
            | "hooks"
            | "plugins"
            | "skills"
            | "commands"
    )
}

fn root_contains_protected_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(value) => protected_directory(value.to_string_lossy().as_ref()),
        _ => false,
    })
}

pub(super) fn named_path_matches_held(path: &Path, held: &Dir) -> bool {
    crate::sidecar::directory_path_matches_held(path, held)
}

pub(super) fn join_relative(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn io_error(path: &str) -> StageError {
    if path.is_empty() {
        StageError::new(StageErrorCode::Io)
    } else {
        StageError::at(StageErrorCode::Io, path.to_owned())
    }
}

#[cfg(windows)]
pub(super) fn root_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_type().is_symlink()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
}

#[cfg(not(windows))]
pub(super) fn root_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn private_parent_is_verified(_path: &Path, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(windows)]
fn private_parent_is_verified(path: &Path, metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.is_dir()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
        && crate::sidecar::windows_security::verify_private_directory(path).is_ok()
}

#[cfg(not(any(unix, windows)))]
fn private_parent_is_verified(_path: &Path, _metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn held_private_directory_is_verified(directory: &Dir) -> bool {
    directory.dir_metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0
    })
}

#[cfg(windows)]
pub(super) fn held_private_directory_is_verified(directory: &Dir) -> bool {
    directory.dir_metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0
    }) && crate::sidecar::windows_security::verify_private_directory_handle(directory).is_ok()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn held_private_directory_is_verified(_directory: &Dir) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn create_private_directory(directory: &Dir, name: &str) -> std::io::Result<Dir> {
    directory.create_dir(name)?;
    directory.set_permissions(name, Permissions::from_mode(0o700))?;
    let child = open_directory_nofollow(directory, name)?;
    let metadata = child.dir_metadata()?;
    if metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
    {
        Ok(child)
    } else {
        Err(private_containment_error())
    }
}

#[cfg(windows)]
pub(super) fn create_private_directory(directory: &Dir, name: &str) -> std::io::Result<Dir> {
    let child =
        crate::sidecar::create_relative_private_directory(directory, std::ffi::OsStr::new(name))
            .map(Dir::from_std_file)
            .map_err(|()| private_containment_error())?;
    let metadata = child.dir_metadata()?;
    if metadata.is_dir()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
        && crate::sidecar::windows_security::verify_private_directory_handle(&child).is_ok()
    {
        Ok(child)
    } else {
        Err(private_containment_error())
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn create_private_directory(_directory: &Dir, _name: &str) -> std::io::Result<Dir> {
    Err(private_containment_error())
}

#[cfg(unix)]
pub(super) fn open_directory_nofollow(
    directory: &Dir,
    name: impl AsRef<Path>,
) -> std::io::Result<Dir> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let child = Dir::from_std_file(directory.open_with(name, &options)?.into_std());
    if child.dir_metadata()?.is_dir() {
        Ok(child)
    } else {
        Err(private_containment_error())
    }
}

#[cfg(windows)]
pub(super) fn open_directory_nofollow(
    directory: &Dir,
    name: impl AsRef<Path>,
) -> std::io::Result<Dir> {
    let parent = directory.try_clone()?.into_std_file();
    let child = cap_primitives::fs::open_dir_nofollow(&parent, name.as_ref())?;
    let child = Dir::from_std_file(child);
    let metadata = child.dir_metadata()?;
    if metadata.is_dir()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
    {
        Ok(child)
    } else {
        Err(private_containment_error())
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_directory_nofollow(
    _directory: &Dir,
    _name: impl AsRef<Path>,
) -> std::io::Result<Dir> {
    Err(private_containment_error())
}

#[cfg(unix)]
pub(super) fn create_private_file(
    directory: &Dir,
    name: &str,
) -> std::io::Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(0o600);
    directory.open_with(name, &options)
}

#[cfg(windows)]
pub(super) fn create_private_file(
    directory: &Dir,
    name: &str,
) -> std::io::Result<cap_std::fs::File> {
    crate::sidecar::create_relative_private_file(directory, std::ffi::OsStr::new(name))
        .map(cap_std::fs::File::from_std)
        .map_err(|()| private_containment_error())
}

#[cfg(not(any(unix, windows)))]
pub(super) fn create_private_file(
    _directory: &Dir,
    _name: &str,
) -> std::io::Result<cap_std::fs::File> {
    Err(private_containment_error())
}

#[cfg(unix)]
pub(super) fn secure_created_file(file: &cap_std::fs::File) -> std::io::Result<()> {
    file.set_permissions(Permissions::from_mode(0o600))?;
    let metadata = file.metadata()?;
    if metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.nlink() == 1
    {
        Ok(())
    } else {
        Err(private_containment_error())
    }
}

#[cfg(windows)]
pub(super) fn secure_created_file(file: &cap_std::fs::File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if opened_metadata_is_regular(&metadata)
        && link_count(&metadata) == Some(1)
        && crate::sidecar::windows_security::verify_private_file_handle(file).is_ok()
    {
        Ok(())
    } else {
        Err(private_containment_error())
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn secure_created_file(_file: &cap_std::fs::File) -> std::io::Result<()> {
    Err(private_containment_error())
}

fn private_containment_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "private stage containment verification failed",
    )
}

#[cfg(unix)]
pub(super) fn set_no_follow(options: &mut OpenOptions) {
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
pub(super) fn set_no_follow(options: &mut OpenOptions) {
    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
pub(super) fn set_no_follow(_options: &mut OpenOptions) {}

#[cfg(windows)]
pub(super) fn entry_is_link_or_reparse(
    entry: &cap_std::fs::DirEntry,
    file_type: &cap_std::fs::FileType,
) -> std::io::Result<bool> {
    Ok(file_type.is_symlink()
        || entry.metadata()?.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0)
}

#[cfg(not(windows))]
pub(super) fn entry_is_link_or_reparse(
    _entry: &cap_std::fs::DirEntry,
    file_type: &cap_std::fs::FileType,
) -> std::io::Result<bool> {
    Ok(file_type.is_symlink())
}

#[cfg(unix)]
fn pre_open_link_count(metadata: &Metadata) -> Option<u64> {
    Some(metadata.nlink())
}

#[cfg(not(unix))]
fn pre_open_link_count(_metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
pub(super) fn link_count(metadata: &Metadata) -> Option<u64> {
    Some(metadata.nlink())
}

#[cfg(windows)]
pub(super) fn link_count(metadata: &Metadata) -> Option<u64> {
    metadata.number_of_links().map(u64::from)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn link_count(_metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(windows)]
pub(super) fn opened_metadata_is_regular(metadata: &Metadata) -> bool {
    metadata.is_file()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
}

#[cfg(not(windows))]
pub(super) fn opened_metadata_is_regular(metadata: &Metadata) -> bool {
    metadata.is_file()
}

#[cfg(unix)]
fn pre_open_matches_opened(before: &Metadata, opened: &Metadata) -> bool {
    same_file(before, opened)
}

#[cfg(not(unix))]
fn pre_open_matches_opened(_before: &Metadata, _opened: &Metadata) -> bool {
    true
}

#[cfg(unix)]
pub(super) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
pub(super) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.volume_serial_number() == right.volume_serial_number()
        && left.file_index() == right.file_index()
        && left.volume_serial_number().is_some()
        && left.file_index().is_some()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
}

fn named_entry_matches(
    entry: &cap_std::fs::DirEntry,
    read_options: &OpenOptions,
    expected: &Metadata,
) -> std::io::Result<bool> {
    let validation_file = entry.open_with(read_options)?;
    let validation_metadata = validation_file.metadata()?;
    Ok(opened_metadata_is_regular(&validation_metadata)
        && link_count(&validation_metadata) == Some(1)
        && validation_metadata.len() == expected.len()
        && same_file(expected, &validation_metadata))
}

#[cfg(unix)]
fn source_identity(metadata: &Metadata) -> Option<SourceIdentity> {
    Some(SourceIdentity {
        platform: "unix",
        identity_a: metadata.dev().to_string(),
        identity_b: metadata.ino().to_string(),
        owner_id: metadata.uid().to_string(),
        owner_mode: Some(metadata.permissions().mode() & 0o7777),
    })
}

#[cfg(windows)]
fn source_identity(metadata: &Metadata) -> Option<SourceIdentity> {
    Some(SourceIdentity {
        platform: "windows",
        identity_a: metadata.volume_serial_number()?.to_string(),
        identity_b: metadata.file_index()?.to_string(),
        // The source workspace is not required to have Carl's private DACL.
        // Promotion revalidates its named identity and content; this marker
        // explicitly records that no owner SID is asserted here.
        owner_id: "not_asserted".to_owned(),
        owner_mode: None,
    })
}

#[cfg(not(any(unix, windows)))]
fn source_identity(_metadata: &Metadata) -> Option<SourceIdentity> {
    None
}
