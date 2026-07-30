use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(windows)]
use cap_primitives::fs::_WindowsByHandle;
#[cfg(any(unix, windows))]
use cap_std::fs::OpenOptionsExt;
use cap_std::fs::{Dir, Metadata, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{MetadataExt, Permissions, PermissionsExt};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::Cell;
use uuid::Uuid;

use crate::runtime::subscription::ArtifactId;
use crate::sidecar::DataRootLock;

use super::{ArtifactError, ArtifactErrorCode};

const OBJECT_DIRECTORY: &str = "objects";
const HASH_DIRECTORY: &str = "sha256";
const TEMPORARY_OBJECT_PREFIX: &str = ".tmp-";
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARTIFACT_STORE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARTIFACT_OBJECTS: u64 = 200_000;
const MAX_ARTIFACT_DIRECTORY_ENTRIES: u64 = 400_000;
const EXISTING_PUBLICATION_RETRIES: usize = 32;

#[cfg(test)]
thread_local! {
    static INJECT_DIRECTORY_SYNC_FAILURE: Cell<bool> = const { Cell::new(false) };
}

pub struct ArtifactStore {
    canonical_root: PathBuf,
    objects: Dir,
    publication_lock: Mutex<ArtifactUsage>,
    _root_lock: DataRootLock,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ArtifactUsage {
    objects: u64,
    bytes: u64,
}

impl ArtifactUsage {
    fn ensure_can_add(self, byte_length: u64) -> Result<(), ArtifactError> {
        let objects = self
            .objects
            .checked_add(1)
            .ok_or_else(|| error(ArtifactErrorCode::LimitExceeded))?;
        let bytes = self
            .bytes
            .checked_add(byte_length)
            .ok_or_else(|| error(ArtifactErrorCode::LimitExceeded))?;
        if objects > MAX_ARTIFACT_OBJECTS || bytes > MAX_ARTIFACT_STORE_BYTES {
            return Err(error(ArtifactErrorCode::LimitExceeded));
        }
        Ok(())
    }

    fn add(&mut self, byte_length: u64) -> Result<(), ArtifactError> {
        self.ensure_can_add(byte_length)?;
        self.include_existing(byte_length)
    }

    fn include_existing(&mut self, byte_length: u64) -> Result<(), ArtifactError> {
        self.objects = self
            .objects
            .checked_add(1)
            .ok_or_else(|| error(ArtifactErrorCode::LimitExceeded))?;
        self.bytes = self
            .bytes
            .checked_add(byte_length)
            .ok_or_else(|| error(ArtifactErrorCode::LimitExceeded))?;
        Ok(())
    }

    fn remove(&mut self, byte_length: u64) -> Result<(), ArtifactError> {
        self.objects = self
            .objects
            .checked_sub(1)
            .ok_or_else(|| error(ArtifactErrorCode::Corrupt))?;
        self.bytes = self
            .bytes
            .checked_sub(byte_length)
            .ok_or_else(|| error(ArtifactErrorCode::Corrupt))?;
        Ok(())
    }
}

impl ArtifactStore {
    /// Open an absolute, pre-existing, owner-private artifact root.
    pub fn open(root: &Path) -> Result<Self, ArtifactError> {
        if !root.is_absolute() {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        let metadata =
            std::fs::symlink_metadata(root).map_err(|_| error(ArtifactErrorCode::InvalidRoot))?;
        if !metadata.is_dir()
            || root_is_link_or_reparse(&metadata)
            || !private_root_is_verified(root, &metadata)
        {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        let canonical =
            std::fs::canonicalize(root).map_err(|_| error(ArtifactErrorCode::InvalidRoot))?;
        let root_lock =
            DataRootLock::acquire(&canonical).map_err(|_| error(ArtifactErrorCode::InvalidRoot))?;
        if !root_lock.guards_data_root(&canonical) {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        let root = root_lock
            .try_clone_root_directory()
            .map(Dir::from_std_file)
            .map_err(|_| error(ArtifactErrorCode::InvalidRoot))?;
        if !held_private_directory_is_verified(&root) {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        let objects = open_or_create_private_directory(&root, OBJECT_DIRECTORY)
            .and_then(|directory| open_or_create_private_directory(&directory, HASH_DIRECTORY))
            .map_err(|_| error(ArtifactErrorCode::InvalidRoot))?;
        if !root_lock.guards_data_root(&canonical) {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        recover_interrupted_publications(&objects)?;
        let usage = scan_artifact_usage(&objects)?;
        Ok(Self {
            canonical_root: canonical,
            objects,
            publication_lock: Mutex::new(usage),
            _root_lock: root_lock,
        })
    }

    pub(crate) fn open_or_create_for_runtime(
        data_root_lock: &DataRootLock,
    ) -> Result<Self, ArtifactError> {
        let data_root = data_root_lock.runtime_data_root();
        if !data_root_lock.guards_data_root(data_root) {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        let artifact_root = data_root.join("artifacts");
        match std::fs::symlink_metadata(&artifact_root) {
            Ok(_) => {}
            Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
                let parent = data_root_lock
                    .try_clone_root_directory()
                    .map(Dir::from_std_file)
                    .map_err(|_| error(ArtifactErrorCode::InvalidRoot))?;
                create_private_directory(&parent, "artifacts")
                    .map(drop)
                    .map_err(|_| error(ArtifactErrorCode::Io))?;
                sync_containing_directory(&parent).map_err(|_| error(ArtifactErrorCode::Io))?;
            }
            Err(_) => return Err(error(ArtifactErrorCode::InvalidRoot)),
        }
        let store = Self::open(&artifact_root)?;
        if !data_root_lock.guards_data_root(data_root) {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        Ok(store)
    }

    /// Persist bytes under their SHA-256 identifier and immediately re-open,
    /// identity-check, and re-hash the canonical object.
    pub fn put(&self, bytes: &[u8]) -> Result<StoredArtifact, ArtifactError> {
        let mut usage = self
            .publication_lock
            .lock()
            .map_err(|_| error(ArtifactErrorCode::Io))?;
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| error(ArtifactErrorCode::LimitExceeded))?;
        if byte_length > MAX_ARTIFACT_BYTES {
            return Err(error(ArtifactErrorCode::LimitExceeded));
        }
        let id = artifact_id(bytes)?;
        let name = id.as_str();
        match self.objects.symlink_metadata(name) {
            Ok(_) => {
                let stored = self.read_existing_publication(&id)?;
                if stored.bytes() != bytes {
                    return Err(error(ArtifactErrorCode::Corrupt));
                }
                sync_containing_directory(&self.objects)
                    .map_err(|_| error(ArtifactErrorCode::Io))?;
                return Ok(stored);
            }
            Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error(ArtifactErrorCode::Io)),
        }
        usage.ensure_can_add(byte_length)?;

        let temporary_name = format!("{TEMPORARY_OBJECT_PREFIX}{}", Uuid::new_v4());
        let mut temporary = create_private_file(&self.objects, &temporary_name)
            .map_err(|_| error(ArtifactErrorCode::Io))?;

        let prepare_result = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| error(ArtifactErrorCode::Io))?;
            temporary
                .sync_all()
                .map_err(|_| error(ArtifactErrorCode::Io))?;
            seal_created_file(&temporary)?;
            temporary
                .sync_all()
                .map_err(|_| error(ArtifactErrorCode::Io))?;
            let prepared = self.read_named_verified(&temporary_name, &id)?;
            if prepared.bytes() != bytes {
                return Err(error(ArtifactErrorCode::Corrupt));
            }
            Ok::<_, ArtifactError>(())
        })();
        if let Err(prepare_error) = prepare_result {
            if remove_temporary_object(&self.objects, &temporary_name, temporary).is_err()
                || sync_containing_directory(&self.objects).is_err()
            {
                return Err(error(ArtifactErrorCode::Io));
            }
            return Err(prepare_error);
        }

        match self.objects.hard_link(&temporary_name, &self.objects, name) {
            Ok(()) => {
                usage.add(byte_length)?;
            }
            Err(io_error) if io_error.kind() == std::io::ErrorKind::AlreadyExists => {
                if remove_temporary_object(&self.objects, &temporary_name, temporary).is_err()
                    || sync_containing_directory(&self.objects).is_err()
                {
                    return Err(error(ArtifactErrorCode::Io));
                }
                return Err(error(ArtifactErrorCode::Corrupt));
            }
            Err(_) => {
                if remove_temporary_object(&self.objects, &temporary_name, temporary).is_err()
                    || sync_containing_directory(&self.objects).is_err()
                {
                    return Err(error(ArtifactErrorCode::Io));
                }
                return Err(error(ArtifactErrorCode::Io));
            }
        }

        if sync_containing_directory(&self.objects).is_err() {
            if remove_temporary_object(&self.objects, &temporary_name, temporary).is_err()
                || sync_containing_directory(&self.objects).is_err()
            {
                return Err(error(ArtifactErrorCode::Io));
            }
            return Err(error(ArtifactErrorCode::Io));
        }
        remove_temporary_object(&self.objects, &temporary_name, temporary)
            .map_err(|_| error(ArtifactErrorCode::Io))?;
        sync_containing_directory(&self.objects).map_err(|_| error(ArtifactErrorCode::Io))?;

        let stored = self.read_verified(&id)?;
        if stored.bytes() != bytes {
            return Err(error(ArtifactErrorCode::Corrupt));
        }
        Ok(stored)
    }

    /// Remove canonical objects that have no durable database root. The runtime
    /// calls this only while it owns both the data-root and artifact-root locks.
    pub(crate) fn retain_only(
        &self,
        referenced: &HashSet<ArtifactId>,
    ) -> Result<(), ArtifactError> {
        let mut usage = self
            .publication_lock
            .lock()
            .map_err(|_| error(ArtifactErrorCode::Io))?;
        let inventory = inspect_artifact_directory(&self.objects)?;
        let mut removed_any = false;

        for (id, byte_length) in inventory.canonical {
            if referenced.contains(&id) {
                continue;
            }
            remove_verified_canonical_object(&self.objects, &id, byte_length)?;
            usage.remove(byte_length)?;
            removed_any = true;
        }
        if removed_any {
            sync_containing_directory(&self.objects).map_err(|_| error(ArtifactErrorCode::Io))?;
        }
        Ok(())
    }

    /// Read one object only after enforcing its regular-file, owner-private,
    /// single-link, read-only, identity, length, and content-address checks.
    pub fn read_verified(&self, id: &ArtifactId) -> Result<StoredArtifact, ArtifactError> {
        self.read_named_verified(id.as_str(), id)
    }

    pub(crate) fn overlaps_canonical_path(&self, path: &Path) -> Result<bool, ArtifactError> {
        if !self._root_lock.guards_data_root(&self.canonical_root) {
            return Err(error(ArtifactErrorCode::InvalidRoot));
        }
        crate::sidecar::directory_paths_overlap(&self.canonical_root, path)
            .map_err(|_| error(ArtifactErrorCode::InvalidRoot))
    }

    fn read_existing_publication(&self, id: &ArtifactId) -> Result<StoredArtifact, ArtifactError> {
        for attempt in 0..EXISTING_PUBLICATION_RETRIES {
            match self.read_verified(id) {
                Ok(stored) => return Ok(stored),
                Err(read_error)
                    if read_error.code() == ArtifactErrorCode::Corrupt
                        && attempt + 1 < EXISTING_PUBLICATION_RETRIES =>
                {
                    std::thread::yield_now();
                }
                Err(read_error) => return Err(read_error),
            }
        }
        Err(error(ArtifactErrorCode::Corrupt))
    }

    fn read_named_verified(
        &self,
        name: &str,
        id: &ArtifactId,
    ) -> Result<StoredArtifact, ArtifactError> {
        let mut options = OpenOptions::new();
        options.read(true);
        set_no_follow(&mut options);
        let mut file = self
            .objects
            .open_with(name, &options)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let initial = file
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        verify_sealed_file(&file, &initial)?;
        if initial.len() > MAX_ARTIFACT_BYTES {
            return Err(error(ArtifactErrorCode::LimitExceeded));
        }
        let identity = file_identity(&initial).ok_or_else(|| error(ArtifactErrorCode::Corrupt))?;

        let mut bytes = Vec::with_capacity(
            usize::try_from(initial.len()).map_err(|_| error(ArtifactErrorCode::LimitExceeded))?,
        );
        (&mut file)
            .take(MAX_ARTIFACT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        if u64::try_from(bytes.len()).ok() != Some(initial.len()) {
            return Err(error(ArtifactErrorCode::Corrupt));
        }
        let final_metadata = file
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        if file_identity(&final_metadata) != Some(identity) || final_metadata.len() != initial.len()
        {
            return Err(error(ArtifactErrorCode::Corrupt));
        }

        let named = self
            .objects
            .open_with(name, &options)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let named_metadata = named
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        verify_sealed_file(&named, &named_metadata)?;
        if file_identity(&named_metadata) != Some(identity)
            || named_metadata.len() != initial.len()
            || artifact_id(&bytes)? != *id
        {
            return Err(error(ArtifactErrorCode::Corrupt));
        }

        Ok(StoredArtifact {
            id: id.clone(),
            bytes,
        })
    }
}

fn scan_artifact_usage(objects: &Dir) -> Result<ArtifactUsage, ArtifactError> {
    inspect_artifact_directory(objects).map(|inventory| inventory.usage)
}

struct ArtifactInventory {
    usage: ArtifactUsage,
    canonical: Vec<(ArtifactId, u64)>,
}

fn inspect_artifact_directory(objects: &Dir) -> Result<ArtifactInventory, ArtifactError> {
    let mut usage = ArtifactUsage::default();
    let mut canonical = Vec::new();
    let mut entries_seen = 0_u64;
    let entries = objects
        .entries()
        .map_err(|_| error(ArtifactErrorCode::Io))?;
    for entry in entries {
        let entry = entry.map_err(|_| error(ArtifactErrorCode::Io))?;
        entries_seen = entries_seen
            .checked_add(1)
            .ok_or_else(|| error(ArtifactErrorCode::LimitExceeded))?;
        if entries_seen > MAX_ARTIFACT_DIRECTORY_ENTRIES {
            return Err(error(ArtifactErrorCode::LimitExceeded));
        }
        let name = entry.file_name();
        let id = name.to_str().and_then(|name| ArtifactId::parse(name).ok());

        let mut options = recovery_temporary_options();
        set_no_follow(&mut options);
        let file = objects
            .open_with(&name, &options)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let metadata = file
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        if let Some(id) = id {
            verify_sealed_file(&file, &metadata)?;
            if metadata.len() > MAX_ARTIFACT_BYTES {
                return Err(error(ArtifactErrorCode::LimitExceeded));
            }
            canonical.push((id, metadata.len()));
        } else {
            verify_private_temporary(&file, &metadata)?;
        }
        usage.include_existing(metadata.len())?;
    }
    Ok(ArtifactInventory { usage, canonical })
}

fn remove_verified_canonical_object(
    objects: &Dir,
    id: &ArtifactId,
    expected_length: u64,
) -> Result<(), ArtifactError> {
    let mut options = recovery_temporary_options();
    set_no_follow(&mut options);
    let file = objects
        .open_with(id.as_str(), &options)
        .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
    let metadata = file
        .metadata()
        .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
    verify_sealed_file(&file, &metadata)?;
    let identity = file_identity(&metadata).ok_or_else(|| error(ArtifactErrorCode::Corrupt))?;
    if metadata.len() != expected_length {
        return Err(error(ArtifactErrorCode::Corrupt));
    }

    let named = objects
        .open_with(id.as_str(), &options)
        .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
    let named_metadata = named
        .metadata()
        .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
    verify_sealed_file(&named, &named_metadata)?;
    if file_identity(&named_metadata) != Some(identity) || named_metadata.len() != expected_length {
        return Err(error(ArtifactErrorCode::Corrupt));
    }
    drop(named);

    remove_temporary_object(objects, id.as_str(), file).map_err(|_| error(ArtifactErrorCode::Io))
}

fn recover_interrupted_publications(objects: &Dir) -> Result<(), ArtifactError> {
    let mut entries_seen = 0_u64;
    let entries = objects
        .entries()
        .map_err(|_| error(ArtifactErrorCode::Io))?;
    for entry in entries {
        let entry = entry.map_err(|_| error(ArtifactErrorCode::Io))?;
        entries_seen = entries_seen
            .checked_add(1)
            .ok_or_else(|| error(ArtifactErrorCode::LimitExceeded))?;
        if entries_seen > MAX_ARTIFACT_DIRECTORY_ENTRIES {
            return Err(error(ArtifactErrorCode::LimitExceeded));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(identifier) = name.strip_prefix(TEMPORARY_OBJECT_PREFIX) else {
            continue;
        };
        if Uuid::parse_str(identifier).is_err() {
            continue;
        }

        let mut temporary_options = recovery_temporary_options();
        set_no_follow(&mut temporary_options);
        let mut temporary = objects
            .open_with(name, &temporary_options)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let initial = temporary
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let Some(identity) = file_identity(&initial) else {
            return Err(error(ArtifactErrorCode::Corrupt));
        };
        match artifact_link_count(&initial) {
            Some(1) => {
                verify_private_temporary(&temporary, &initial)?;
                remove_temporary_object(objects, name, temporary)
                    .map_err(|_| error(ArtifactErrorCode::Io))?;
                sync_containing_directory(objects).map_err(|_| error(ArtifactErrorCode::Io))?;
                continue;
            }
            Some(2) => {}
            _ => return Err(error(ArtifactErrorCode::Corrupt)),
        }
        verify_recoverable_publication(&temporary, &initial)?;
        if initial.len() > MAX_ARTIFACT_BYTES {
            return Err(error(ArtifactErrorCode::LimitExceeded));
        }

        let mut bytes = Vec::with_capacity(
            usize::try_from(initial.len()).map_err(|_| error(ArtifactErrorCode::LimitExceeded))?,
        );
        (&mut temporary)
            .take(MAX_ARTIFACT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let final_metadata = temporary
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        if u64::try_from(bytes.len()).ok() != Some(initial.len())
            || file_identity(&final_metadata) != Some(identity)
            || artifact_link_count(&final_metadata) != Some(2)
        {
            return Err(error(ArtifactErrorCode::Corrupt));
        }

        let id = artifact_id(&bytes)?;
        let mut canonical_options = OpenOptions::new();
        canonical_options.read(true);
        set_no_follow(&mut canonical_options);
        let canonical = objects
            .open_with(id.as_str(), &canonical_options)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let canonical_metadata = canonical
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        verify_recoverable_publication(&canonical, &canonical_metadata)?;
        if file_identity(&canonical_metadata) != Some(identity)
            || artifact_link_count(&canonical_metadata) != Some(2)
        {
            return Err(error(ArtifactErrorCode::Corrupt));
        }
        drop(canonical);

        remove_temporary_object(objects, name, temporary)
            .map_err(|_| error(ArtifactErrorCode::Io))?;
        sync_containing_directory(objects).map_err(|_| error(ArtifactErrorCode::Io))?;

        let canonical = objects
            .open_with(id.as_str(), &canonical_options)
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        let canonical_metadata = canonical
            .metadata()
            .map_err(|_| error(ArtifactErrorCode::Corrupt))?;
        verify_sealed_file(&canonical, &canonical_metadata)?;
        if file_identity(&canonical_metadata) != Some(identity) {
            return Err(error(ArtifactErrorCode::Corrupt));
        }
    }
    Ok(())
}

impl fmt::Debug for ArtifactStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactStore")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredArtifact {
    id: ArtifactId,
    bytes: Vec<u8>,
}

impl StoredArtifact {
    #[must_use]
    pub const fn id(&self) -> &ArtifactId {
        &self.id
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for StoredArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredArtifact")
            .field("id", &self.id)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

fn artifact_id(bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
    ArtifactId::parse(format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| error(ArtifactErrorCode::Corrupt))
}

fn error(code: ArtifactErrorCode) -> ArtifactError {
    ArtifactError::new(code)
}

fn open_or_create_private_directory(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    match open_directory_nofollow(parent, name) {
        Ok(directory) if held_private_directory_is_verified(&directory) => Ok(directory),
        Ok(_) => Err(private_error()),
        Err(_) => {
            let directory = create_private_directory(parent, name)?;
            sync_containing_directory(parent)?;
            Ok(directory)
        }
    }
}

#[cfg(unix)]
fn create_private_directory(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    parent.create_dir(name)?;
    parent.set_permissions(name, Permissions::from_mode(0o700))?;
    let directory = open_directory_nofollow(parent, name)?;
    if held_private_directory_is_verified(&directory) {
        Ok(directory)
    } else {
        Err(private_error())
    }
}

#[cfg(windows)]
fn create_private_directory(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    let directory =
        crate::sidecar::create_relative_private_directory(parent, std::ffi::OsStr::new(name))
            .map(Dir::from_std_file)
            .map_err(|()| private_error())?;
    if held_private_directory_is_verified(&directory) {
        Ok(directory)
    } else {
        Err(private_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(_parent: &Dir, _name: &str) -> std::io::Result<Dir> {
    Err(private_error())
}

#[cfg(unix)]
fn open_directory_nofollow(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = Dir::from_std_file(parent.open_with(name, &options)?.into_std());
    if directory.dir_metadata()?.is_dir() {
        Ok(directory)
    } else {
        Err(private_error())
    }
}

#[cfg(windows)]
fn open_directory_nofollow(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    let parent = parent.try_clone()?.into_std_file();
    let directory = Dir::from_std_file(cap_primitives::fs::open_dir_nofollow(
        &parent,
        Path::new(name),
    )?);
    let metadata = directory.dir_metadata()?;
    if metadata.is_dir()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
    {
        Ok(directory)
    } else {
        Err(private_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn open_directory_nofollow(_parent: &Dir, _name: &str) -> std::io::Result<Dir> {
    Err(private_error())
}

#[cfg(unix)]
fn create_private_file(parent: &Dir, name: &str) -> std::io::Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(0o600);
    parent.open_with(name, &options)
}

#[cfg(windows)]
fn create_private_file(parent: &Dir, name: &str) -> std::io::Result<cap_std::fs::File> {
    crate::sidecar::create_relative_private_file(parent, std::ffi::OsStr::new(name))
        .map(cap_std::fs::File::from_std)
        .map_err(|()| private_error())
}

#[cfg(not(any(unix, windows)))]
fn create_private_file(_parent: &Dir, _name: &str) -> std::io::Result<cap_std::fs::File> {
    Err(private_error())
}

#[cfg(unix)]
fn recovery_temporary_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    options
}

#[cfg(windows)]
fn recovery_temporary_options() -> OpenOptions {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        READ_CONTROL,
    };

    let mut options = OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | DELETE | READ_CONTROL);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    options
}

#[cfg(not(any(unix, windows)))]
fn recovery_temporary_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(unix)]
fn remove_temporary_object(
    parent: &Dir,
    name: &str,
    file: cap_std::fs::File,
) -> std::io::Result<()> {
    let remove_result = parent.remove_file(name);
    drop(file);
    remove_result
}

#[cfg(windows)]
fn remove_temporary_object(
    _parent: &Dir,
    _name: &str,
    file: cap_std::fs::File,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx,
        SetFileInformationByHandle,
    };

    let information = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: create_relative_private_file opened this live handle with DELETE
    // access, and information points to the exact disposition structure required
    // by FileDispositionInfoEx for the duration of the call.
    let removed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&information).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO_EX>())
                .map_err(|_| private_error())?,
        )
    };
    let result = if removed == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    };
    drop(file);
    result
}

#[cfg(not(any(unix, windows)))]
fn remove_temporary_object(
    _parent: &Dir,
    _name: &str,
    _file: cap_std::fs::File,
) -> std::io::Result<()> {
    Err(private_error())
}

#[cfg(unix)]
fn sync_containing_directory(directory: &Dir) -> std::io::Result<()> {
    if directory_sync_failure_injected() {
        return Err(std::io::Error::other(
            "injected artifact directory sync failure",
        ));
    }
    directory.try_clone()?.into_std_file().sync_all()
}

#[cfg(windows)]
fn sync_containing_directory(directory: &Dir) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Wdk::Storage::FileSystem::NtFlushBuffersFileEx;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    if directory_sync_failure_injected() {
        return Err(std::io::Error::other(
            "injected artifact directory sync failure",
        ));
    }
    let directory = crate::sidecar::reopen_private_directory_for_flush(directory)?;
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: directory owns a live filesystem handle, the normal flush mode
    // accepts directory handles, parameters are absent as required, and status
    // points to writable storage for the duration of the synchronous call.
    let result = unsafe {
        NtFlushBuffersFileEx(
            directory.as_raw_handle(),
            0,
            std::ptr::null(),
            0,
            &mut status,
        )
    };
    if result >= 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "directory metadata could not be flushed",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn sync_containing_directory(_directory: &Dir) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
fn directory_sync_failure_injected() -> bool {
    INJECT_DIRECTORY_SYNC_FAILURE.with(Cell::get)
}

#[cfg(not(test))]
const fn directory_sync_failure_injected() -> bool {
    false
}

#[cfg(unix)]
fn seal_created_file(file: &cap_std::fs::File) -> Result<(), ArtifactError> {
    file.set_permissions(Permissions::from_mode(0o400))
        .map_err(|_| error(ArtifactErrorCode::Io))?;
    let metadata = file.metadata().map_err(|_| error(ArtifactErrorCode::Io))?;
    verify_unix_sealed_metadata(&metadata)
}

#[cfg(windows)]
fn seal_created_file(file: &cap_std::fs::File) -> Result<(), ArtifactError> {
    let mut permissions = file
        .metadata()
        .map_err(|_| error(ArtifactErrorCode::Io))?
        .permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .map_err(|_| error(ArtifactErrorCode::Io))?;
    let metadata = file.metadata().map_err(|_| error(ArtifactErrorCode::Io))?;
    verify_windows_sealed_file(file, &metadata)
}

#[cfg(not(any(unix, windows)))]
fn seal_created_file(_file: &cap_std::fs::File) -> Result<(), ArtifactError> {
    Err(error(ArtifactErrorCode::Io))
}

#[cfg(unix)]
fn artifact_link_count(metadata: &Metadata) -> Option<u64> {
    Some(metadata.nlink())
}

#[cfg(windows)]
fn artifact_link_count(metadata: &Metadata) -> Option<u64> {
    metadata.number_of_links().map(u64::from)
}

#[cfg(not(any(unix, windows)))]
fn artifact_link_count(_metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn verify_private_temporary(
    _file: &cap_std::fs::File,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    if metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o077 == 0
    {
        Ok(())
    } else {
        Err(error(ArtifactErrorCode::Corrupt))
    }
}

#[cfg(windows)]
fn verify_private_temporary(
    file: &cap_std::fs::File,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    if metadata.is_file()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
        && metadata.number_of_links() == Some(1)
        && crate::sidecar::windows_security::verify_private_file_handle(file).is_ok()
    {
        Ok(())
    } else {
        Err(error(ArtifactErrorCode::Corrupt))
    }
}

#[cfg(not(any(unix, windows)))]
fn verify_private_temporary(
    _file: &cap_std::fs::File,
    _metadata: &Metadata,
) -> Result<(), ArtifactError> {
    Err(error(ArtifactErrorCode::Corrupt))
}

#[cfg(unix)]
fn verify_recoverable_publication(
    _file: &cap_std::fs::File,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    if metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.nlink() == 2
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.permissions().mode() & 0o222 == 0
    {
        Ok(())
    } else {
        Err(error(ArtifactErrorCode::Corrupt))
    }
}

#[cfg(windows)]
fn verify_recoverable_publication(
    file: &cap_std::fs::File,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    if metadata.is_file()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY
            != 0
        && metadata.number_of_links() == Some(2)
        && crate::sidecar::windows_security::verify_private_file_handle(file).is_ok()
    {
        Ok(())
    } else {
        Err(error(ArtifactErrorCode::Corrupt))
    }
}

#[cfg(not(any(unix, windows)))]
fn verify_recoverable_publication(
    _file: &cap_std::fs::File,
    _metadata: &Metadata,
) -> Result<(), ArtifactError> {
    Err(error(ArtifactErrorCode::Corrupt))
}

#[cfg(unix)]
fn verify_sealed_file(_file: &cap_std::fs::File, metadata: &Metadata) -> Result<(), ArtifactError> {
    verify_unix_sealed_metadata(metadata)
}

#[cfg(unix)]
fn verify_unix_sealed_metadata(metadata: &Metadata) -> Result<(), ArtifactError> {
    if metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.permissions().mode() & 0o222 == 0
    {
        Ok(())
    } else {
        Err(error(ArtifactErrorCode::Corrupt))
    }
}

#[cfg(windows)]
fn verify_sealed_file(file: &cap_std::fs::File, metadata: &Metadata) -> Result<(), ArtifactError> {
    verify_windows_sealed_file(file, metadata)
}

#[cfg(windows)]
fn verify_windows_sealed_file(
    file: &cap_std::fs::File,
    metadata: &Metadata,
) -> Result<(), ArtifactError> {
    if metadata.is_file()
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            == 0
        && metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY
            != 0
        && metadata.number_of_links() == Some(1)
        && crate::sidecar::windows_security::verify_private_file_handle(file).is_ok()
    {
        Ok(())
    } else {
        Err(error(ArtifactErrorCode::Corrupt))
    }
}

#[cfg(not(any(unix, windows)))]
fn verify_sealed_file(
    _file: &cap_std::fs::File,
    _metadata: &Metadata,
) -> Result<(), ArtifactError> {
    Err(error(ArtifactErrorCode::Corrupt))
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume: u32,
    index: u64,
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    Some(FileIdentity {
        volume: metadata.volume_serial_number()?,
        index: metadata.file_index()?,
    })
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity;

#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(unix)]
fn held_private_directory_is_verified(directory: &Dir) -> bool {
    directory.dir_metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0
    })
}

#[cfg(windows)]
fn held_private_directory_is_verified(directory: &Dir) -> bool {
    directory.dir_metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0
    }) && crate::sidecar::windows_security::verify_private_directory_handle(directory).is_ok()
}

#[cfg(not(any(unix, windows)))]
fn held_private_directory_is_verified(_directory: &Dir) -> bool {
    false
}

#[cfg(unix)]
fn private_root_is_verified(_path: &Path, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(windows)]
fn private_root_is_verified(path: &Path, metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        == 0
        && crate::sidecar::windows_security::verify_private_directory(path).is_ok()
}

#[cfg(not(any(unix, windows)))]
fn private_root_is_verified(_path: &Path, _metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn root_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_type().is_symlink()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
}

#[cfg(not(windows))]
fn root_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
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

fn private_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "private artifact containment verification failed",
    )
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(windows)]
    use std::path::Path;

    #[cfg(any(unix, windows))]
    use uuid::Uuid;

    use super::{ArtifactErrorCode, ArtifactUsage, MAX_ARTIFACT_OBJECTS, MAX_ARTIFACT_STORE_BYTES};
    #[cfg(unix)]
    use super::{ArtifactStore, INJECT_DIRECTORY_SYNC_FAILURE};
    #[cfg(windows)]
    use super::{
        OBJECT_DIRECTORY, create_private_directory, held_private_directory_is_verified,
        private_root_is_verified, sync_containing_directory,
    };
    #[cfg(windows)]
    use crate::sidecar::DataRootLock;

    #[test]
    fn aggregate_quota_admission_is_bounded_and_overflow_safe() {
        let mut usage = ArtifactUsage {
            objects: MAX_ARTIFACT_OBJECTS - 1,
            bytes: MAX_ARTIFACT_STORE_BYTES - 1,
        };
        usage.add(1).expect("the exact quota boundary is valid");
        assert_eq!(usage.objects, MAX_ARTIFACT_OBJECTS);
        assert_eq!(usage.bytes, MAX_ARTIFACT_STORE_BYTES);
        assert_eq!(
            usage
                .ensure_can_add(0)
                .expect_err("one more object exceeds the count quota")
                .code(),
            ArtifactErrorCode::LimitExceeded
        );

        let bytes_full = ArtifactUsage {
            objects: 0,
            bytes: MAX_ARTIFACT_STORE_BYTES,
        };
        assert_eq!(
            bytes_full
                .ensure_can_add(1)
                .expect_err("one more byte exceeds the byte quota")
                .code(),
            ArtifactErrorCode::LimitExceeded
        );
        assert_eq!(
            ArtifactUsage {
                objects: u64::MAX,
                bytes: u64::MAX,
            }
            .ensure_can_add(u64::MAX)
            .expect_err("integer overflow must fail closed")
            .code(),
            ArtifactErrorCode::LimitExceeded
        );

        let mut legacy_over_quota = ArtifactUsage::default();
        legacy_over_quota
            .include_existing(MAX_ARTIFACT_STORE_BYTES + 1)
            .expect("startup accounting allows GC to inspect legacy over-quota state");
        assert_eq!(
            legacy_over_quota
                .ensure_can_add(0)
                .expect_err("new unique objects remain blocked until GC lowers usage")
                .code(),
            ArtifactErrorCode::LimitExceeded
        );
    }

    #[cfg(windows)]
    #[test]
    fn fresh_private_root_supports_each_artifact_bootstrap_boundary() {
        let root = std::env::temp_dir().join(format!(
            "carl-artifact-windows-bootstrap-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("create private artifact root");
        make_owner_only(&root).expect("secure private artifact root");

        let metadata = fs::symlink_metadata(&root).expect("inspect private artifact root");
        assert!(
            private_root_is_verified(&root, &metadata),
            "path-based private-root verification failed"
        );
        let canonical = fs::canonicalize(&root).expect("canonicalize private artifact root");
        let root_lock = DataRootLock::acquire(&canonical)
            .unwrap_or_else(|error| panic!("data-root lock failed: {:?}", error.code()));
        assert!(
            root_lock.guards_data_root(&canonical),
            "data-root lock did not retain the root identity"
        );
        let root_directory = root_lock
            .try_clone_root_directory()
            .map(cap_std::fs::Dir::from_std_file)
            .expect("clone held artifact root");
        assert!(
            held_private_directory_is_verified(&root_directory),
            "handle-based private-root verification failed"
        );

        let objects = create_private_directory(&root_directory, OBJECT_DIRECTORY)
            .unwrap_or_else(|error| panic!("objects directory creation failed: {error:?}"));
        sync_containing_directory(&root_directory)
            .unwrap_or_else(|error| panic!("artifact-root directory flush failed: {error:?}"));
        let hashes = create_private_directory(&objects, super::HASH_DIRECTORY)
            .unwrap_or_else(|error| panic!("hash directory creation failed: {error:?}"));
        sync_containing_directory(&objects)
            .unwrap_or_else(|error| panic!("objects directory flush failed: {error:?}"));

        drop(hashes);
        drop(objects);
        drop(root_directory);
        drop(root_lock);
        fs::remove_dir_all(root).expect("remove private artifact root");
    }

    #[cfg(unix)]
    #[test]
    fn publication_propagates_a_directory_sync_failure() {
        let root = std::env::temp_dir().join(format!("carl-sync-failure-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("create private artifact root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure private artifact root");
        let store = ArtifactStore::open(&root).expect("open artifact store");

        INJECT_DIRECTORY_SYNC_FAILURE.with(|injected| injected.set(true));
        let bytes = b"must not be reported durable";
        let result = store.put(bytes);
        let retry_while_sync_still_fails = store.put(bytes);
        INJECT_DIRECTORY_SYNC_FAILURE.with(|injected| injected.set(false));
        assert_eq!(
            result
                .expect_err("a directory sync failure must abort publication")
                .code(),
            ArtifactErrorCode::Io
        );
        assert_eq!(
            retry_while_sync_still_fails
                .expect_err("an existing but unproven publication must retry directory sync")
                .code(),
            ArtifactErrorCode::Io
        );
        assert_eq!(
            store
                .put(bytes)
                .expect("publication succeeds only after directory sync recovers")
                .bytes(),
            bytes
        );

        drop(store);
        fs::remove_dir_all(root).expect("remove artifact fixture");
    }

    #[cfg(windows)]
    fn make_owner_only(path: &Path) -> std::io::Result<()> {
        let identity = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()?;
        if !identity.status.success() {
            return Err(std::io::Error::other(
                "the Windows fixture could not resolve the current identity",
            ));
        }
        let sid_start = identity
            .stdout
            .windows(4)
            .position(|window| window == b"S-1-")
            .ok_or_else(|| std::io::Error::other("whoami returned no current-user SID"))?;
        let sid_end = identity.stdout[sid_start..]
            .iter()
            .position(|byte| !byte.is_ascii_digit() && *byte != b'-' && *byte != b'S')
            .map_or(identity.stdout.len(), |offset| sid_start + offset);
        let sid = std::str::from_utf8(&identity.stdout[sid_start..sid_end])
            .map_err(|_| std::io::Error::other("whoami returned an invalid SID"))?;
        let numeric_identity = format!("*{sid}");
        let owner_status = std::process::Command::new("icacls")
            .arg(path)
            .arg("/setowner")
            .arg(&numeric_identity)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !owner_status.success() {
            return Err(std::io::Error::other(
                "the Windows fixture could not set the current user as owner",
            ));
        }
        let grant = format!("{numeric_identity}:(OI)(CI)F");
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
            Err(std::io::Error::other(
                "the Windows fixture could not install a private DACL",
            ))
        }
    }
}
