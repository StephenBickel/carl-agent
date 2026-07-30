use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;

#[cfg(windows)]
use cap_primitives::fs::_WindowsByHandle;
use cap_std::fs::{Dir, Metadata, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{MetadataExt, PermissionsExt};
use sha2::{Digest, Sha256};

use crate::artifacts::{ArtifactId, ArtifactStore};
use crate::policy::Sha256Digest;
use crate::security::{SecretFilter, SecretRule};

#[cfg(windows)]
use super::builder::held_private_directory_is_verified;
use super::builder::{
    build_manifest, entry_is_link_or_reparse, excluded_file, join_relative, link_count,
    open_directory_nofollow, opened_metadata_is_regular, protected_directory, same_file,
    set_no_follow,
};
use super::{SanitizedStage, SealedBaseline, StageManifestEntry, account_path_bytes};

const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 64;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const PROPOSAL_DOMAIN: &[u8] = b"carl.exact-replacement.v1\0";
const DIRECTORY_MANIFEST_DOMAIN: &[u8] = b"carl.baseline-directories.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalErrorCode {
    InvalidLimits,
    CreatedFile,
    DeletedFile,
    RenamedFile,
    MultipleFiles,
    RedirectedPath,
    HardLink,
    NonUtf8,
    ProtectedPath,
    LimitExceeded,
    MetadataChanged,
    SecretDetected,
    EntryChanged,
    ArtifactCorrupt,
    Io,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProposalError {
    code: ProposalErrorCode,
    path: Option<String>,
    secret_rule: Option<SecretRule>,
}

impl ProposalError {
    const fn new(code: ProposalErrorCode) -> Self {
        Self {
            code,
            path: None,
            secret_rule: None,
        }
    }

    fn at(code: ProposalErrorCode, path: impl Into<String>) -> Self {
        Self {
            code,
            path: Some(path.into()),
            secret_rule: None,
        }
    }

    fn secret(path: impl Into<String>, rule: SecretRule) -> Self {
        Self {
            code: ProposalErrorCode::SecretDetected,
            path: Some(path.into()),
            secret_rule: Some(rule),
        }
    }

    pub(crate) const fn from_stage_io() -> Self {
        Self::new(ProposalErrorCode::Io)
    }

    #[must_use]
    pub const fn code(&self) -> ProposalErrorCode {
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

impl fmt::Debug for ProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalError")
            .field("code", &self.code)
            .field("path", &self.path)
            .field("secret_rule", &self.secret_rule)
            .finish()
    }
}

impl fmt::Display for ProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            ProposalErrorCode::InvalidLimits => "Proposal inspection limits are invalid.",
            ProposalErrorCode::CreatedFile => "The stage contains a created entry.",
            ProposalErrorCode::DeletedFile => "The stage contains a deleted entry.",
            ProposalErrorCode::RenamedFile => "The stage contains a renamed file.",
            ProposalErrorCode::MultipleFiles => "The stage changes more than one file.",
            ProposalErrorCode::RedirectedPath => "The stage contains a redirected path.",
            ProposalErrorCode::HardLink => "The stage contains a hard-linked file.",
            ProposalErrorCode::NonUtf8 => "The replacement is not UTF-8 text.",
            ProposalErrorCode::ProtectedPath => "The stage contains a protected path.",
            ProposalErrorCode::LimitExceeded => "The stage exceeds a proposal inspection limit.",
            ProposalErrorCode::MetadataChanged => "The stage changes protected metadata.",
            ProposalErrorCode::SecretDetected => {
                "The replacement contains high-confidence secret material."
            }
            ProposalErrorCode::EntryChanged => {
                "A stage entry changed while Carl was inspecting it."
            }
            ProposalErrorCode::ArtifactCorrupt => {
                "A sealed baseline or proposal artifact failed verification."
            }
            ProposalErrorCode::Io => "The stage could not be inspected safely.",
        })
    }
}

impl std::error::Error for ProposalError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalLimits {
    max_file_bytes: u64,
}

impl ProposalLimits {
    pub fn new(max_file_bytes: u64) -> Result<Self, ProposalError> {
        if max_file_bytes == 0 || max_file_bytes > MAX_FILE_BYTES {
            return Err(ProposalError::new(ProposalErrorCode::InvalidLimits));
        }
        Ok(Self { max_file_bytes })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ProposalOutcome {
    NoChanges,
    ExactReplacement(Box<ExactReplacementProposal>),
}

impl fmt::Debug for ProposalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoChanges => formatter.write_str("NoChanges"),
            Self::ExactReplacement(proposal) => formatter
                .debug_tuple("ExactReplacement")
                .field(proposal)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExactReplacementProposal {
    artifact_id: ArtifactId,
    payload_artifact_id: ArtifactId,
    baseline_manifest_digest: Sha256Digest,
    candidate_manifest_digest: Sha256Digest,
    path: String,
    expected_live_hash: Sha256Digest,
    before_hash: Sha256Digest,
    after_hash: Sha256Digest,
    payload_hash: Sha256Digest,
    payload: Vec<u8>,
}

impl ExactReplacementProposal {
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub const fn payload_artifact_id(&self) -> &ArtifactId {
        &self.payload_artifact_id
    }

    #[must_use]
    pub const fn baseline_manifest_digest(&self) -> Sha256Digest {
        self.baseline_manifest_digest
    }

    #[must_use]
    pub const fn candidate_manifest_digest(&self) -> Sha256Digest {
        self.candidate_manifest_digest
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn expected_live_hash(&self) -> Sha256Digest {
        self.expected_live_hash
    }

    #[must_use]
    pub const fn before_hash(&self) -> Sha256Digest {
        self.before_hash
    }

    #[must_use]
    pub const fn after_hash(&self) -> Sha256Digest {
        self.after_hash
    }

    #[must_use]
    pub const fn payload_hash(&self) -> Sha256Digest {
        self.payload_hash
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn canonical_envelope(&self) -> Vec<u8> {
        canonical_proposal_envelope(
            self.baseline_manifest_digest,
            &self.path,
            self.expected_live_hash,
            self.before_hash,
            self.after_hash,
            self.payload_hash,
            &self.payload,
        )
        .expect("validated proposal fields always encode")
    }
}

impl fmt::Debug for ExactReplacementProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactReplacementProposal")
            .field("artifact_id", &self.artifact_id)
            .field("path", &self.path)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl SanitizedStage {
    pub fn inspect_proposal(
        &self,
        artifacts: &ArtifactStore,
        limits: ProposalLimits,
        secret_filter: SecretFilter,
    ) -> Result<ProposalOutcome, ProposalError> {
        verify_baseline(artifacts, &self.baseline)?;
        let work_root = self
            .work_root
            .as_ref()
            .ok_or_else(|| ProposalError::new(ProposalErrorCode::Io))?;
        verify_work_directory(work_root, "")?;

        let first = scan_stage(work_root, limits, secret_filter)?;
        let second = scan_stage(work_root, limits, secret_filter)?;
        ensure_stable_scan(&first, &second)?;
        inspect_snapshot(artifacts, &self.baseline, first)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct StageSnapshot {
    files: BTreeMap<String, ScannedFile>,
    directories: BTreeMap<String, ScannedDirectory>,
    entry_count: usize,
    path_bytes: usize,
    total_bytes: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CandidateSnapshotSeal {
    snapshot: StageSnapshot,
    manifest_digest: Sha256Digest,
    directory_manifest_digest: Sha256Digest,
}

impl CandidateSnapshotSeal {
    pub(crate) const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }

    pub(crate) const fn directory_manifest_digest(&self) -> Sha256Digest {
        self.directory_manifest_digest
    }

    pub(crate) fn matches_expected_manifest(
        &self,
        manifest_digest: Sha256Digest,
        directory_manifest_digest: Sha256Digest,
    ) -> bool {
        self.manifest_digest == manifest_digest
            && self.directory_manifest_digest == directory_manifest_digest
    }

    pub(crate) fn same_persistent_snapshot(&self, other: &Self) -> bool {
        self.snapshot == other.snapshot
            && self.manifest_digest == other.manifest_digest
            && self.directory_manifest_digest == other.directory_manifest_digest
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ScannedFile {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    identity: EntryIdentity,
    metadata_valid: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ScannedDirectory {
    identity: EntryIdentity,
    metadata_valid: bool,
}

pub(crate) fn inspect_verification_candidate(
    root: &Dir,
    expected_entries: &[StageManifestEntry],
    expected_directories: &[String],
    limits: ProposalLimits,
    secret_filter: SecretFilter,
) -> Result<CandidateSnapshotSeal, ProposalError> {
    verify_work_directory(root, "")?;
    let first = scan_stage(root, limits, secret_filter)?;
    let second = scan_stage(root, limits, secret_filter)?;
    ensure_stable_scan(&first, &second)?;
    seal_expected_snapshot(first, expected_entries, expected_directories)
}

fn seal_expected_snapshot(
    snapshot: StageSnapshot,
    expected_entries: &[StageManifestEntry],
    expected_directories: &[String],
) -> Result<CandidateSnapshotSeal, ProposalError> {
    let mut previous_path: Option<&str> = None;
    let mut expected_total = 0_u64;
    for expected in expected_entries {
        if previous_path.is_some_and(|previous| previous >= expected.path()) {
            return Err(ProposalError::new(ProposalErrorCode::EntryChanged));
        }
        let scanned = snapshot.files.get(expected.path()).ok_or_else(|| {
            ProposalError::at(ProposalErrorCode::EntryChanged, expected.path().to_owned())
        })?;
        if !scanned.metadata_valid
            || scanned.bytes.len() as u64 != expected.bytes()
            || scanned.digest != expected.content_digest()
        {
            return Err(ProposalError::at(
                ProposalErrorCode::EntryChanged,
                expected.path().to_owned(),
            ));
        }
        expected_total = expected_total
            .checked_add(expected.bytes())
            .ok_or_else(|| ProposalError::new(ProposalErrorCode::LimitExceeded))?;
        previous_path = Some(expected.path());
    }
    if snapshot.files.len() != expected_entries.len() || snapshot.total_bytes != expected_total {
        let unexpected = snapshot
            .files
            .keys()
            .find(|path| {
                expected_entries
                    .binary_search_by(|entry| entry.path().cmp(path.as_str()))
                    .is_err()
            })
            .cloned()
            .unwrap_or_default();
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            unexpected,
        ));
    }

    let expected_directory_set = expected_directories
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected_directory_set.len() != expected_directories.len()
        || snapshot.directories.len() != expected_directories.len()
        || snapshot.directories.iter().any(|(path, directory)| {
            !directory.metadata_valid || !expected_directory_set.contains(path.as_str())
        })
    {
        let unexpected = snapshot
            .directories
            .keys()
            .find(|path| !expected_directory_set.contains(path.as_str()))
            .cloned()
            .unwrap_or_default();
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            unexpected,
        ));
    }
    let directory_manifest = canonical_directory_manifest(expected_directories)?;
    let manifest = build_manifest(expected_total, expected_entries.to_vec())
        .map_err(|_| ProposalError::new(ProposalErrorCode::EntryChanged))?;
    Ok(CandidateSnapshotSeal {
        snapshot,
        manifest_digest: manifest.digest(),
        directory_manifest_digest: digest(&directory_manifest),
    })
}

fn canonical_directory_manifest(directories: &[String]) -> Result<Vec<u8>, ProposalError> {
    let mut bytes = Vec::new();
    let mut previous: Option<&str> = None;
    let mut path_bytes = 0_usize;
    bytes.extend_from_slice(DIRECTORY_MANIFEST_DOMAIN);
    bytes.extend_from_slice(
        &u32::try_from(directories.len())
            .map_err(|_| ProposalError::new(ProposalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for directory in directories {
        if directory.is_empty()
            || directory.len() > MAX_RELATIVE_PATH_BYTES
            || directory.contains('\\')
            || directory.starts_with('/')
            || directory.ends_with('/')
            || directory
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
            || previous.is_some_and(|previous| previous >= directory.as_str())
        {
            return Err(ProposalError::at(
                ProposalErrorCode::EntryChanged,
                directory.clone(),
            ));
        }
        if let Some((parent, _)) = directory.rsplit_once('/')
            && directories
                .binary_search_by(|candidate| candidate.as_str().cmp(parent))
                .is_err()
        {
            return Err(ProposalError::at(
                ProposalErrorCode::EntryChanged,
                directory.clone(),
            ));
        }
        account_path_bytes(&mut path_bytes, directory)
            .map_err(|()| ProposalError::at(ProposalErrorCode::LimitExceeded, directory.clone()))?;
        bytes.extend_from_slice(
            &u32::try_from(directory.len())
                .map_err(|_| {
                    ProposalError::at(ProposalErrorCode::LimitExceeded, directory.clone())
                })?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(directory.as_bytes());
        previous = Some(directory);
    }
    Ok(bytes)
}

fn verify_baseline(
    artifacts: &ArtifactStore,
    baseline: &SealedBaseline,
) -> Result<(), ProposalError> {
    let manifest = artifacts
        .read_verified(baseline.manifest_artifact_id())
        .map_err(|_| ProposalError::new(ProposalErrorCode::ArtifactCorrupt))?;
    let expected_manifest = baseline
        .manifest()
        .canonical_bytes()
        .map_err(|_| ProposalError::new(ProposalErrorCode::ArtifactCorrupt))?;
    if manifest.bytes() != expected_manifest {
        return Err(ProposalError::new(ProposalErrorCode::ArtifactCorrupt));
    }

    for entry in baseline.entries() {
        let artifact = artifacts
            .read_verified(entry.content_artifact_id())
            .map_err(|_| {
                ProposalError::at(ProposalErrorCode::ArtifactCorrupt, entry.path().to_owned())
            })?;
        if artifact.bytes().len() as u64 != entry.bytes()
            || digest(artifact.bytes()) != entry.content_digest()
        {
            return Err(ProposalError::at(
                ProposalErrorCode::ArtifactCorrupt,
                entry.path().to_owned(),
            ));
        }
    }
    Ok(())
}

fn inspect_snapshot(
    artifacts: &ArtifactStore,
    baseline: &SealedBaseline,
    snapshot: StageSnapshot,
) -> Result<ProposalOutcome, ProposalError> {
    let baseline_directories = baseline
        .directories()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let current_directories = snapshot
        .directories
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if let Some(created) = current_directories.difference(&baseline_directories).next() {
        return Err(ProposalError::at(
            ProposalErrorCode::CreatedFile,
            (*created).to_owned(),
        ));
    }
    if let Some(deleted) = baseline_directories.difference(&current_directories).next() {
        return Err(ProposalError::at(
            ProposalErrorCode::DeletedFile,
            (*deleted).to_owned(),
        ));
    }
    if let Some((path, _)) = snapshot.directories.iter().find(|(path, directory)| {
        baseline_directories.contains(path.as_str()) && !directory.metadata_valid
    }) {
        return Err(ProposalError::at(
            ProposalErrorCode::MetadataChanged,
            path.clone(),
        ));
    }

    let baseline_entries = baseline
        .entries()
        .iter()
        .map(|entry| (entry.path(), entry))
        .collect::<BTreeMap<_, _>>();
    let current_paths = snapshot
        .files
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let baseline_paths = baseline_entries.keys().copied().collect::<BTreeSet<_>>();
    let created = current_paths
        .difference(&baseline_paths)
        .copied()
        .collect::<Vec<_>>();
    let deleted = baseline_paths
        .difference(&current_paths)
        .copied()
        .collect::<Vec<_>>();

    if created.len() == 1 && deleted.len() == 1 {
        let created_file = &snapshot.files[created[0]];
        let deleted_file = baseline_entries[deleted[0]];
        if created_file.digest == deleted_file.content_digest() {
            return Err(ProposalError::at(
                ProposalErrorCode::RenamedFile,
                deleted[0].to_owned(),
            ));
        }
    }
    if let Some(path) = created.first() {
        return Err(ProposalError::at(
            ProposalErrorCode::CreatedFile,
            (*path).to_owned(),
        ));
    }
    if let Some(path) = deleted.first() {
        return Err(ProposalError::at(
            ProposalErrorCode::DeletedFile,
            (*path).to_owned(),
        ));
    }
    if let Some((path, _)) = snapshot
        .files
        .iter()
        .find(|(path, file)| baseline_paths.contains(path.as_str()) && !file.metadata_valid)
    {
        return Err(ProposalError::at(
            ProposalErrorCode::MetadataChanged,
            path.clone(),
        ));
    }

    let changed = baseline_entries
        .iter()
        .filter_map(|(path, baseline_entry)| {
            let current = &snapshot.files[*path];
            (current.digest != baseline_entry.content_digest()).then_some(*path)
        })
        .collect::<Vec<_>>();
    if changed.is_empty() {
        return Ok(ProposalOutcome::NoChanges);
    }
    if changed.len() > 1 {
        return Err(ProposalError::at(
            ProposalErrorCode::MultipleFiles,
            changed[1].to_owned(),
        ));
    }

    let path = changed[0];
    let before_entry = baseline_entries[path];
    let before = artifacts
        .read_verified(before_entry.content_artifact_id())
        .map_err(|_| ProposalError::at(ProposalErrorCode::ArtifactCorrupt, path.to_owned()))?;
    let after = &snapshot.files[path];
    let payload_artifact = artifacts
        .put(&after.bytes)
        .map_err(|_| ProposalError::at(ProposalErrorCode::ArtifactCorrupt, path.to_owned()))?;
    if payload_artifact.id().as_str() != after.digest.to_string() {
        return Err(ProposalError::at(
            ProposalErrorCode::ArtifactCorrupt,
            path.to_owned(),
        ));
    }

    let candidate_manifest_digest = candidate_manifest_digest(baseline, path, after)?;
    let envelope = canonical_proposal_envelope(
        baseline.manifest().digest(),
        path,
        before_entry.content_digest(),
        before_entry.content_digest(),
        after.digest,
        after.digest,
        &after.bytes,
    )?;
    let proposal_artifact = artifacts
        .put(&envelope)
        .map_err(|_| ProposalError::at(ProposalErrorCode::ArtifactCorrupt, path.to_owned()))?;
    let proposal = ExactReplacementProposal {
        artifact_id: proposal_artifact.id().clone(),
        payload_artifact_id: payload_artifact.id().clone(),
        baseline_manifest_digest: baseline.manifest().digest(),
        candidate_manifest_digest,
        path: path.to_owned(),
        expected_live_hash: before_entry.content_digest(),
        before_hash: digest(before.bytes()),
        after_hash: after.digest,
        payload_hash: digest(payload_artifact.bytes()),
        payload: payload_artifact.bytes().to_vec(),
    };
    if proposal.before_hash != before_entry.content_digest()
        || proposal.after_hash != proposal.payload_hash
        || proposal.canonical_envelope() != envelope
    {
        return Err(ProposalError::at(
            ProposalErrorCode::ArtifactCorrupt,
            path.to_owned(),
        ));
    }
    Ok(ProposalOutcome::ExactReplacement(Box::new(proposal)))
}

fn candidate_manifest_digest(
    baseline: &SealedBaseline,
    changed_path: &str,
    after: &ScannedFile,
) -> Result<Sha256Digest, ProposalError> {
    let mut entries = baseline.manifest().entries().to_vec();
    let mut found = false;
    for entry in &mut entries {
        if entry.path() == changed_path {
            *entry = StageManifestEntry::new(
                changed_path.to_owned(),
                after.bytes.len() as u64,
                after.digest,
            );
            found = true;
            break;
        }
    }
    if !found {
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            changed_path.to_owned(),
        ));
    }
    let total_bytes = baseline
        .manifest()
        .total_bytes()
        .checked_sub(
            baseline
                .entries()
                .iter()
                .find(|entry| entry.path() == changed_path)
                .ok_or_else(|| {
                    ProposalError::at(ProposalErrorCode::EntryChanged, changed_path.to_owned())
                })?
                .bytes(),
        )
        .and_then(|bytes| bytes.checked_add(after.bytes.len() as u64))
        .ok_or_else(|| {
            ProposalError::at(ProposalErrorCode::LimitExceeded, changed_path.to_owned())
        })?;
    build_manifest(total_bytes, entries)
        .map(|manifest| manifest.digest())
        .map_err(|_| ProposalError::at(ProposalErrorCode::EntryChanged, changed_path.to_owned()))
}

pub(crate) fn canonical_proposal_envelope(
    baseline: Sha256Digest,
    path: &str,
    expected_live: Sha256Digest,
    before: Sha256Digest,
    after: Sha256Digest,
    payload_hash: Sha256Digest,
    payload: &[u8],
) -> Result<Vec<u8>, ProposalError> {
    let path_len = u32::try_from(path.len())
        .map_err(|_| ProposalError::at(ProposalErrorCode::LimitExceeded, path.to_owned()))?;
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| ProposalError::at(ProposalErrorCode::LimitExceeded, path.to_owned()))?;
    let mut bytes = Vec::with_capacity(
        PROPOSAL_DOMAIN.len() + 32 + 4 + path.len() + (32 * 4) + 8 + payload.len(),
    );
    bytes.extend_from_slice(PROPOSAL_DOMAIN);
    bytes.extend_from_slice(baseline.as_bytes());
    bytes.extend_from_slice(&path_len.to_be_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(expected_live.as_bytes());
    bytes.extend_from_slice(before.as_bytes());
    bytes.extend_from_slice(after.as_bytes());
    bytes.extend_from_slice(payload_hash.as_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn scan_stage(
    root: &Dir,
    limits: ProposalLimits,
    secret_filter: SecretFilter,
) -> Result<StageSnapshot, ProposalError> {
    let mut snapshot = StageSnapshot {
        files: BTreeMap::new(),
        directories: BTreeMap::new(),
        entry_count: 0,
        path_bytes: 0,
        total_bytes: 0,
    };
    scan_directory(root, "", 0, limits, secret_filter, &mut snapshot)?;
    Ok(snapshot)
}

fn scan_directory(
    directory: &Dir,
    relative_parent: &str,
    depth: usize,
    limits: ProposalLimits,
    secret_filter: SecretFilter,
    snapshot: &mut StageSnapshot,
) -> Result<(), ProposalError> {
    if depth > MAX_DEPTH {
        return Err(ProposalError::at(
            ProposalErrorCode::LimitExceeded,
            relative_parent.to_owned(),
        ));
    }
    let remaining_entries = MAX_ENTRIES.saturating_sub(snapshot.entry_count);
    let mut entries = directory
        .entries()
        .map_err(|_| io_error(relative_parent))?
        .take(remaining_entries.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io_error(relative_parent))?;
    if entries.len() > remaining_entries {
        return Err(ProposalError::at(
            ProposalErrorCode::LimitExceeded,
            relative_parent.to_owned(),
        ));
    }
    snapshot.entry_count = snapshot
        .entry_count
        .checked_add(entries.len())
        .ok_or_else(|| {
            ProposalError::at(ProposalErrorCode::LimitExceeded, relative_parent.to_owned())
        })?;
    entries.sort_by_key(cap_std::fs::DirEntry::file_name);

    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            ProposalError::at(ProposalErrorCode::EntryChanged, relative_parent.to_owned())
        })?;
        if name == "." || name == ".." || name.contains(['/', '\\']) {
            return Err(ProposalError::at(
                ProposalErrorCode::EntryChanged,
                relative_parent.to_owned(),
            ));
        }
        let relative = join_relative(relative_parent, name);
        if relative.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(ProposalError::at(
                ProposalErrorCode::LimitExceeded,
                relative,
            ));
        }
        account_path_bytes(&mut snapshot.path_bytes, &relative)
            .map_err(|()| ProposalError::at(ProposalErrorCode::LimitExceeded, relative.clone()))?;
        let file_type = entry.file_type().map_err(|_| io_error(&relative))?;
        if entry_is_link_or_reparse(&entry, &file_type).map_err(|_| io_error(&relative))? {
            return Err(ProposalError::at(
                ProposalErrorCode::RedirectedPath,
                relative,
            ));
        }
        if protected_directory(name) {
            return Err(ProposalError::at(
                ProposalErrorCode::ProtectedPath,
                relative,
            ));
        }
        if file_type.is_dir() {
            let child = open_directory_nofollow(directory, name).map_err(|_| {
                ProposalError::at(ProposalErrorCode::EntryChanged, relative.clone())
            })?;
            let identity = directory_identity(&child).ok_or_else(|| {
                ProposalError::at(ProposalErrorCode::EntryChanged, relative.clone())
            })?;
            snapshot.directories.insert(
                relative.clone(),
                ScannedDirectory {
                    identity,
                    metadata_valid: work_directory_metadata_valid(&child),
                },
            );
            scan_directory(
                &child,
                &relative,
                depth + 1,
                limits,
                secret_filter,
                snapshot,
            )?;
            continue;
        }
        if !file_type.is_file() {
            return Err(ProposalError::at(
                ProposalErrorCode::RedirectedPath,
                relative,
            ));
        }
        if excluded_file(&relative, name).is_some() {
            return Err(ProposalError::at(
                ProposalErrorCode::ProtectedPath,
                relative,
            ));
        }
        let file = read_work_file(&entry, &relative, limits, secret_filter)?;
        snapshot.total_bytes = snapshot
            .total_bytes
            .checked_add(file.bytes.len() as u64)
            .ok_or_else(|| ProposalError::at(ProposalErrorCode::LimitExceeded, relative.clone()))?;
        if snapshot.total_bytes > MAX_TOTAL_BYTES {
            return Err(ProposalError::at(
                ProposalErrorCode::LimitExceeded,
                relative,
            ));
        }
        snapshot.files.insert(relative, file);
    }
    Ok(())
}

fn read_work_file(
    entry: &cap_std::fs::DirEntry,
    relative: &str,
    limits: ProposalLimits,
    secret_filter: SecretFilter,
) -> Result<ScannedFile, ProposalError> {
    let before = entry.metadata().map_err(|_| io_error(relative))?;
    if matches!(link_count(&before), Some(count) if count != 1) {
        return Err(ProposalError::at(
            ProposalErrorCode::HardLink,
            relative.to_owned(),
        ));
    }
    run_before_file_open_test_hook(relative);
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow(&mut options);
    let mut file = entry
        .open_with(&options)
        .map_err(|_| ProposalError::at(ProposalErrorCode::EntryChanged, relative.to_owned()))?;
    let opened = file.metadata().map_err(|_| io_error(relative))?;
    if !opened_metadata_is_regular(&opened) || !pre_open_matches_opened(&before, &opened) {
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            relative.to_owned(),
        ));
    }
    if link_count(&opened) != Some(1) {
        return Err(ProposalError::at(
            ProposalErrorCode::HardLink,
            relative.to_owned(),
        ));
    }
    let mut metadata_valid = work_file_metadata_valid(&file, &opened);
    if opened.len() > limits.max_file_bytes {
        return Err(ProposalError::at(
            ProposalErrorCode::LimitExceeded,
            relative.to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&mut file)
        .take(limits.max_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| io_error(relative))?;
    if bytes.len() as u64 != opened.len() {
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            relative.to_owned(),
        ));
    }
    let final_metadata = file.metadata().map_err(|_| io_error(relative))?;
    if !same_file(&opened, &final_metadata)
        || final_metadata.len() != opened.len()
        || link_count(&final_metadata) != Some(1)
    {
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            relative.to_owned(),
        ));
    }
    let named = entry
        .open_with(&options)
        .map_err(|_| ProposalError::at(ProposalErrorCode::EntryChanged, relative.to_owned()))?;
    let named_metadata = named.metadata().map_err(|_| io_error(relative))?;
    if !same_file(&final_metadata, &named_metadata) || named_metadata.len() != opened.len() {
        return Err(ProposalError::at(
            ProposalErrorCode::EntryChanged,
            relative.to_owned(),
        ));
    }
    metadata_valid &= work_file_metadata_valid(&named, &named_metadata);
    if std::str::from_utf8(&bytes).is_err() {
        return Err(ProposalError::at(
            ProposalErrorCode::NonUtf8,
            relative.to_owned(),
        ));
    }
    if let Err(finding) = secret_filter.inspect(&bytes) {
        if finding.rule() == SecretRule::NonUtf8 {
            return Err(ProposalError::at(
                ProposalErrorCode::NonUtf8,
                relative.to_owned(),
            ));
        }
        return Err(ProposalError::secret(relative.to_owned(), finding.rule()));
    }
    Ok(ScannedFile {
        digest: digest(&bytes),
        bytes,
        identity: file_identity(&final_metadata).ok_or_else(|| {
            ProposalError::at(ProposalErrorCode::EntryChanged, relative.to_owned())
        })?,
        metadata_valid,
    })
}

#[cfg(unix)]
fn pre_open_matches_opened(before: &Metadata, opened: &Metadata) -> bool {
    same_file(before, opened)
}

#[cfg(not(unix))]
fn pre_open_matches_opened(_before: &Metadata, _opened: &Metadata) -> bool {
    true
}

fn ensure_stable_scan(first: &StageSnapshot, second: &StageSnapshot) -> Result<(), ProposalError> {
    if first == second {
        return Ok(());
    }
    let paths = first
        .files
        .keys()
        .chain(second.files.keys())
        .chain(first.directories.keys())
        .chain(second.directories.keys())
        .collect::<BTreeSet<_>>();
    let changed = paths
        .into_iter()
        .find(|path| {
            first.files.get(*path) != second.files.get(*path)
                || first.directories.get(*path) != second.directories.get(*path)
        })
        .map_or_else(String::new, Clone::clone);
    Err(ProposalError::at(ProposalErrorCode::EntryChanged, changed))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn io_error(path: &str) -> ProposalError {
    if path.is_empty() {
        ProposalError::new(ProposalErrorCode::Io)
    } else {
        ProposalError::at(ProposalErrorCode::Io, path.to_owned())
    }
}

#[cfg(test)]
type BeforeFileOpenHook = Box<dyn FnOnce(&str) + Send>;

#[cfg(test)]
static BEFORE_FILE_OPEN_HOOK: std::sync::Mutex<Option<BeforeFileOpenHook>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn run_before_file_open_test_hook(path: &str) {
    let hook = BEFORE_FILE_OPEN_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_before_file_open_test_hook(_path: &str) {}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<EntryIdentity> {
    Some(EntryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn directory_identity(directory: &Dir) -> Option<EntryIdentity> {
    directory
        .dir_metadata()
        .ok()
        .and_then(|metadata| file_identity(&metadata))
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct EntryIdentity {
    volume: u32,
    index: u64,
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> Option<EntryIdentity> {
    Some(EntryIdentity {
        volume: metadata.volume_serial_number()?,
        index: metadata.file_index()?,
    })
}

#[cfg(windows)]
fn directory_identity(directory: &Dir) -> Option<EntryIdentity> {
    directory
        .dir_metadata()
        .ok()
        .and_then(|metadata| file_identity(&metadata))
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct EntryIdentity;

#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &Metadata) -> Option<EntryIdentity> {
    None
}

#[cfg(not(any(unix, windows)))]
fn directory_identity(_directory: &Dir) -> Option<EntryIdentity> {
    None
}

#[cfg(unix)]
fn work_directory_metadata_valid(directory: &Dir) -> bool {
    directory.dir_metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o700
    })
}

#[cfg(windows)]
fn work_directory_metadata_valid(directory: &Dir) -> bool {
    held_private_directory_is_verified(directory)
}

#[cfg(not(any(unix, windows)))]
fn work_directory_metadata_valid(_directory: &Dir) -> bool {
    false
}

fn verify_work_directory(directory: &Dir, path: &str) -> Result<(), ProposalError> {
    if work_directory_metadata_valid(directory) {
        Ok(())
    } else {
        Err(ProposalError::at(
            ProposalErrorCode::MetadataChanged,
            path.to_owned(),
        ))
    }
}

#[cfg(unix)]
fn work_file_metadata_valid(_file: &cap_std::fs::File, metadata: &Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o777 == 0o600
}

#[cfg(windows)]
fn work_file_metadata_valid(file: &cap_std::fs::File, metadata: &Metadata) -> bool {
    opened_metadata_is_regular(metadata)
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY
            == 0
        && crate::sidecar::windows_security::verify_private_file_handle(file).is_ok()
}

#[cfg(not(any(unix, windows)))]
fn work_file_metadata_valid(_file: &cap_std::fs::File, _metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use uuid::Uuid;

    use super::*;
    use crate::staging::{SanitizedStageBuilder, StageLimits};

    #[cfg(unix)]
    #[test]
    fn a_named_file_swap_between_metadata_and_open_fails_closed() {
        let layout = TestLayout::new();
        fs::write(layout.source.join("file.txt"), b"aaaa").expect("write source");
        let store = ArtifactStore::open(&layout.artifacts).expect("open artifact store");
        let stage = SanitizedStageBuilder::open(
            &layout.source,
            &layout.stages,
            StageLimits::new(10, 1_024, 4_096).expect("limits"),
            SecretFilter,
        )
        .expect("builder")
        .prepare(&store)
        .expect("prepare");
        let stage_path = stage.path().to_path_buf();
        *BEFORE_FILE_OPEN_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(move |path| {
            assert_eq!(path, "file.txt");
            fs::rename(stage_path.join("file.txt"), stage_path.join("original.txt"))
                .expect("move original");
            fs::write(stage_path.join("file.txt"), b"bbbb").expect("replace named entry");
        }));

        let error = stage
            .inspect_proposal(
                &store,
                ProposalLimits::new(1_024).expect("proposal limits"),
                SecretFilter,
            )
            .expect_err("a path swap must be rejected");
        assert_eq!(error.code(), ProposalErrorCode::EntryChanged);
        assert_eq!(error.path(), Some("file.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn dir_entry_metadata_without_handle_identity_can_precede_a_verified_open() {
        let layout = TestLayout::new();
        fs::write(layout.source.join("file.txt"), b"unchanged").expect("write source");
        let source = Dir::open_ambient_dir(&layout.source, cap_std::ambient_authority())
            .expect("open source");
        let entry = source
            .entries()
            .expect("read source")
            .next()
            .expect("source entry")
            .expect("read source entry");
        let before = entry.metadata().expect("read directory-entry metadata");
        let mut options = OpenOptions::new();
        options.read(true);
        set_no_follow(&mut options);
        let opened_file = entry.open_with(&options).expect("open source entry");
        let opened = opened_file.metadata().expect("read opened metadata");

        assert!(
            file_identity(&before).is_none(),
            "the fixture must reproduce metadata without by-handle identity"
        );
        assert!(
            file_identity(&opened).is_some(),
            "the opened handle must expose a stable identity"
        );
        assert!(pre_open_matches_opened(&before, &opened));
    }

    struct TestLayout {
        root: PathBuf,
        source: PathBuf,
        stages: PathBuf,
        artifacts: PathBuf,
    }

    impl TestLayout {
        fn new() -> Self {
            #[cfg(unix)]
            let temporary_root = PathBuf::from("/tmp");
            #[cfg(not(unix))]
            let temporary_root = std::env::temp_dir();
            let root = temporary_root.join(format!("carl-proposal-race-{}", Uuid::new_v4()));
            let source = root.join("source");
            let stages = root.join("stages");
            let artifacts = root.join("artifacts");
            for path in [&source, &stages, &artifacts] {
                fs::create_dir_all(path).expect("create private fixture");
            }
            for path in [&root, &source, &stages, &artifacts] {
                make_owner_only(path).expect("secure private fixture");
            }
            Self {
                root,
                source,
                stages,
                artifacts,
            }
        }
    }

    impl Drop for TestLayout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn make_owner_only(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }

    #[cfg(windows)]
    fn make_owner_only(path: &Path) -> std::io::Result<()> {
        let identity = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()?;
        if !identity.status.success() {
            return Err(std::io::Error::other("could not resolve current identity"));
        }
        let sid_start = identity
            .stdout
            .windows(4)
            .position(|window| window == b"S-1-")
            .ok_or_else(|| std::io::Error::other("whoami returned no SID"))?;
        let sid_end = identity.stdout[sid_start..]
            .iter()
            .position(|byte| !byte.is_ascii_digit() && *byte != b'-' && *byte != b'S')
            .map_or(identity.stdout.len(), |offset| sid_start + offset);
        let sid = std::str::from_utf8(&identity.stdout[sid_start..sid_end])
            .map_err(|_| std::io::Error::other("whoami returned an invalid SID"))?;
        let identity = format!("*{sid}");
        let owner = std::process::Command::new("icacls")
            .arg(path)
            .arg("/setowner")
            .arg(&identity)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !owner.success() {
            return Err(std::io::Error::other("could not set fixture owner"));
        }
        let grant = format!("{identity}:(OI)(CI)F");
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(grant)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("could not set private fixture DACL"))
        }
    }
}
