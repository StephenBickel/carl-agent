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

use crate::policy::Sha256Digest;
use crate::security::{SecretFilter, SecretRule};

use super::{
    SanitizedStage, StageError, StageErrorCode, StageExclusion, StageExclusionReason, StageLimits,
    StageManifest, StageManifestEntry,
};

const MAX_DEPTH: usize = 64;

pub struct SanitizedStageBuilder {
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
            || source_metadata.file_type().is_symlink()
            || parent_metadata.file_type().is_symlink()
        {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }
        if !owner_only(&parent_metadata) {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        let source_path = std::fs::canonicalize(source)
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        let stage_parent_path = std::fs::canonicalize(stage_parent)
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        if source_path.starts_with(&stage_parent_path)
            || stage_parent_path.starts_with(&source_path)
            || root_contains_protected_component(&stage_parent_path)
        {
            return Err(StageError::new(StageErrorCode::InvalidRoot));
        }

        let stage_parent_display_path = stage_parent.to_path_buf();
        let source = Dir::open_ambient_dir(&source_path, ambient_authority())
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;
        let stage_parent = Dir::open_ambient_dir(&stage_parent_path, ambient_authority())
            .map_err(|_| StageError::new(StageErrorCode::InvalidRoot))?;

        Ok(Self {
            stage_parent_display_path,
            source,
            stage_parent,
            limits,
            secret_filter,
        })
    }

    pub fn prepare(self) -> Result<SanitizedStage, StageError> {
        let directory_name = format!("stage-{}", Uuid::new_v4());
        self.stage_parent
            .create_dir(&directory_name)
            .map_err(|_| StageError::new(StageErrorCode::Io))?;
        if set_directory_owner_only(&self.stage_parent, &directory_name).is_err() {
            let _ = self.stage_parent.remove_dir_all(&directory_name);
            return Err(StageError::new(StageErrorCode::Io));
        }
        let destination = match self.stage_parent.open_dir(&directory_name) {
            Ok(destination) => destination,
            Err(_) => {
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(StageError::new(StageErrorCode::Io));
            }
        };

        let mut state = BuildState::new(self.limits, self.secret_filter);
        let walk_result = walk_directory(&self.source, &destination, "", 0, &mut state);
        drop(destination);
        if let Err(error) = walk_result {
            let _ = self.stage_parent.remove_dir_all(&directory_name);
            return Err(error);
        }

        state
            .entries
            .sort_by(|left, right| left.path().cmp(right.path()));
        state
            .exclusions
            .sort_by(|left, right| left.path().cmp(right.path()));
        let manifest = match build_manifest(state.total_bytes, state.entries) {
            Ok(manifest) => manifest,
            Err(error) => {
                let _ = self.stage_parent.remove_dir_all(&directory_name);
                return Err(error);
            }
        };
        let path = self.stage_parent_display_path.join(&directory_name);

        Ok(SanitizedStage::new(
            path,
            self.stage_parent,
            directory_name,
            manifest,
            state.exclusions,
        ))
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

struct BuildState {
    limits: StageLimits,
    secret_filter: SecretFilter,
    total_bytes: u64,
    entries: Vec<StageManifestEntry>,
    exclusions: Vec<StageExclusion>,
}

impl BuildState {
    fn new(limits: StageLimits, secret_filter: SecretFilter) -> Self {
        Self {
            limits,
            secret_filter,
            total_bytes: 0,
            entries: Vec::new(),
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
    state: &mut BuildState,
) -> Result<(), StageError> {
    if depth > MAX_DEPTH {
        return Err(StageError::at(
            StageErrorCode::LimitExceeded,
            relative_parent.to_owned(),
        ));
    }

    let mut entries = source
        .entries()
        .map_err(|_| io_error(relative_parent))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io_error(relative_parent))?;
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
        let file_type = entry.file_type().map_err(|_| io_error(&relative))?;

        if file_type.is_symlink() {
            state.exclude(relative, StageExclusionReason::Symlink);
            continue;
        }
        if file_type.is_dir() {
            if protected_directory(name) {
                state.exclude(relative, StageExclusionReason::ProtectedPath);
                continue;
            }
            destination
                .create_dir(name)
                .map_err(|_| io_error(&relative))?;
            set_directory_owner_only(destination, name).map_err(|_| io_error(&relative))?;
            let source_child = entry.open_dir().map_err(|_| io_error(&relative))?;
            let destination_child = destination
                .open_dir(name)
                .map_err(|_| io_error(&relative))?;
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
    state: &mut BuildState,
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

    let mut write_options = OpenOptions::new();
    write_options.write(true).create_new(true);
    set_new_file_mode(&mut write_options);
    let mut destination_file = destination
        .open_with(name, &write_options)
        .map_err(|_| io_error(&relative))?;
    destination_file
        .write_all(&contents)
        .map_err(|_| io_error(&relative))?;
    set_file_owner_only(&destination_file).map_err(|_| io_error(&relative))?;

    state.total_bytes = prospective_total;
    let content_digest = Sha256Digest::from_bytes(Sha256::digest(&contents).into());
    state.entries.push(StageManifestEntry::new(
        relative,
        contents.len() as u64,
        content_digest,
    ));
    Ok(())
}

fn build_manifest(
    total_bytes: u64,
    entries: Vec<StageManifestEntry>,
) -> Result<StageManifest, StageError> {
    let mut hasher = Sha256::new();
    for entry in &entries {
        let path = entry.path().as_bytes();
        let path_len =
            u32::try_from(path.len()).map_err(|_| StageError::new(StageErrorCode::InvalidEntry))?;
        hasher.update(path_len.to_be_bytes());
        hasher.update(path);
        hasher.update(entry.bytes().to_be_bytes());
        hasher.update(entry.content_digest().as_bytes());
        let stage_file = Path::new(entry.path());
        if stage_file.is_absolute()
            || stage_file
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StageError::new(StageErrorCode::InvalidEntry));
        }
    }
    let digest_bytes: [u8; 32] = hasher.finalize().into();
    let digest_text = digest_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let digest = Sha256Digest::parse(&digest_text)
        .map_err(|_| StageError::new(StageErrorCode::InvalidEntry))?;
    Ok(StageManifest::new(digest, total_bytes, entries))
}

fn excluded_file(relative: &str, name: &str) -> Option<StageExclusionReason> {
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

fn protected_directory(name: &str) -> bool {
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

fn join_relative(parent: &str, name: &str) -> String {
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

#[cfg(unix)]
fn owner_only(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn owner_only(_metadata: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn set_directory_owner_only(directory: &Dir, name: &str) -> std::io::Result<()> {
    directory.set_permissions(name, Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_directory_owner_only(_directory: &Dir, _name: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_new_file_mode(options: &mut OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_new_file_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_file_owner_only(file: &cap_std::fs::File) -> std::io::Result<()> {
    file.set_permissions(Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_file_owner_only(_file: &cap_std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn set_no_follow(options: &mut OpenOptions) {
    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn set_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn pre_open_link_count(metadata: &Metadata) -> Option<u64> {
    Some(metadata.nlink())
}

#[cfg(not(unix))]
fn pre_open_link_count(_metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn link_count(metadata: &Metadata) -> Option<u64> {
    Some(metadata.nlink())
}

#[cfg(windows)]
fn link_count(metadata: &Metadata) -> Option<u64> {
    metadata.number_of_links().map(u64::from)
}

#[cfg(not(any(unix, windows)))]
fn link_count(_metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(windows)]
fn opened_metadata_is_regular(metadata: &Metadata) -> bool {
    metadata.is_file()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
}

#[cfg(not(windows))]
fn opened_metadata_is_regular(metadata: &Metadata) -> bool {
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
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.volume_serial_number() == right.volume_serial_number()
        && left.file_index() == right.file_index()
        && left.volume_serial_number().is_some()
        && left.file_index().is_some()
}

#[cfg(not(any(unix, windows)))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
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
