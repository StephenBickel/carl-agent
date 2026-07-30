use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use carl::artifacts::{ArtifactErrorCode, ArtifactStore};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const PAYLOAD: &[u8] = b"stable artifact payload\n";
const PAYLOAD_ID: &str = "d77eac9e8ad31542e9e8cd3c5a8a92d944c4577e47e4640db241bc588d7b8c78";
const DEBUG_PAYLOAD_SENTINEL: &str = "artifact-payload-must-not-appear-in-debug";
const DEBUG_PATH_SENTINEL: &str = "artifact-path-must-not-appear-in-debug";

struct StoreLayout {
    root: PathBuf,
}

impl StoreLayout {
    fn new() -> TestResult<Self> {
        Self::with_label("carl-artifact")
    }

    fn with_label(label: &str) -> TestResult<Self> {
        #[cfg(unix)]
        let temporary_root = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let temporary_root = std::env::temp_dir();

        let root = temporary_root.join(format!("{label}-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        make_owner_only(&root)?;
        Ok(Self { root })
    }

    fn private_directory(&self, name: &str) -> TestResult<PathBuf> {
        let path = self.root.join(name);
        fs::create_dir(&path)?;
        make_owner_only(&path)?;
        Ok(path)
    }
}

impl Drop for StoreLayout {
    fn drop(&mut self) {
        #[cfg(windows)]
        clear_readonly_files(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn identical_bytes_have_one_literal_identity_across_independent_roots() -> TestResult {
    let layout = StoreLayout::new()?;
    let first_root = layout.private_directory("first")?;
    let second_root = layout.private_directory("second")?;
    let first = ArtifactStore::open(&first_root)?;
    let second = ArtifactStore::open(&second_root)?;

    let first_artifact = first.put(PAYLOAD)?;
    let duplicate = first.put(PAYLOAD)?;
    let second_artifact = second.put(PAYLOAD)?;

    assert_eq!(first_artifact.id().as_str(), PAYLOAD_ID);
    assert_eq!(duplicate.id(), first_artifact.id());
    assert_eq!(second_artifact.id(), first_artifact.id());
    assert_eq!(first_artifact.bytes(), PAYLOAD);
    assert_eq!(first.read_verified(first_artifact.id())?.bytes(), PAYLOAD);
    assert_eq!(second.read_verified(second_artifact.id())?.bytes(), PAYLOAD);
    Ok(())
}

#[test]
fn concurrent_publication_never_exposes_a_partial_canonical_object() -> TestResult {
    const WRITERS: usize = 6;
    const PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

    let layout = StoreLayout::new()?;
    let store = Arc::new(ArtifactStore::open(&layout.root)?);
    let payload = Arc::new(vec![b'x'; PAYLOAD_BYTES]);
    let start = Arc::new(Barrier::new(WRITERS));
    let writers = (0..WRITERS)
        .map(|_| {
            let store = Arc::clone(&store);
            let payload = Arc::clone(&payload);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                store.put(payload.as_slice())
            })
        })
        .collect::<Vec<_>>();

    let mut ids = Vec::with_capacity(WRITERS);
    for writer in writers {
        let stored = writer
            .join()
            .map_err(|_| std::io::Error::other("artifact writer panicked"))??;
        assert_eq!(stored.bytes(), payload.as_slice());
        ids.push(stored.id().clone());
    }

    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(
        temporary_object_names(&layout.root)?.is_empty(),
        "successful publication must remove every writer's private temporary object"
    );
    assert_eq!(
        fs::read_dir(objects_directory(&layout.root))?.count(),
        1,
        "all writers must converge on exactly one canonical object"
    );
    Ok(())
}

#[test]
fn successful_and_deduplicated_publication_leave_no_temporary_objects() -> TestResult {
    let layout = StoreLayout::new()?;
    let store = ArtifactStore::open(&layout.root)?;

    let first = store.put(PAYLOAD)?;
    let duplicate = store.put(PAYLOAD)?;

    assert_eq!(duplicate.id(), first.id());
    assert!(temporary_object_names(&layout.root)?.is_empty());
    Ok(())
}

#[test]
fn reopening_repairs_a_crash_between_publication_and_temp_unlink() -> TestResult {
    let layout = StoreLayout::new()?;
    let id = {
        let store = ArtifactStore::open(&layout.root)?;
        store.put(PAYLOAD)?.id().clone()
    };
    let interrupted_temp = objects_directory(&layout.root).join(format!(".tmp-{}", Uuid::new_v4()));
    fs::hard_link(object_path(&layout.root, id.as_str()), &interrupted_temp)?;

    let reopened = ArtifactStore::open(&layout.root)?;
    assert_eq!(reopened.read_verified(&id)?.bytes(), PAYLOAD);
    assert!(!interrupted_temp.exists());
    Ok(())
}

#[test]
fn reopening_removes_a_private_temp_left_before_publication() -> TestResult {
    let layout = StoreLayout::new()?;
    {
        let _store = ArtifactStore::open(&layout.root)?;
    }
    let interrupted_temp = objects_directory(&layout.root).join(format!(".tmp-{}", Uuid::new_v4()));
    fs::write(&interrupted_temp, b"partial pre-publication bytes")?;
    make_file_owner_private(&interrupted_temp)?;

    let _reopened = ArtifactStore::open(&layout.root)?;
    assert!(!interrupted_temp.exists());
    Ok(())
}

#[test]
fn one_artifact_root_has_exactly_one_live_store_owner() -> TestResult {
    let layout = StoreLayout::new()?;
    let first = ArtifactStore::open(&layout.root)?;
    let error = ArtifactStore::open(&layout.root)
        .expect_err("a second store owner must not race publication or recovery");
    assert_eq!(error.code(), ArtifactErrorCode::InvalidRoot);
    drop(first);

    let reopened = ArtifactStore::open(&layout.root)?;
    assert_eq!(reopened.put(PAYLOAD)?.bytes(), PAYLOAD);
    Ok(())
}

#[test]
fn a_stale_temporary_object_does_not_poison_the_canonical_identity() -> TestResult {
    let layout = StoreLayout::new()?;
    let store = ArtifactStore::open(&layout.root)?;
    let stale_name = ".tmp-stale-interrupted-publication";
    let stale_path = objects_directory(&layout.root).join(stale_name);
    fs::write(&stale_path, b"partial bytes from an interrupted writer")?;

    let stored = store.put(PAYLOAD)?;

    assert_eq!(stored.id().as_str(), PAYLOAD_ID);
    assert_eq!(stored.bytes(), PAYLOAD);
    assert_eq!(fs::read(object_path(&layout.root, PAYLOAD_ID))?, PAYLOAD);
    assert_eq!(
        fs::read(stale_path)?,
        b"partial bytes from an interrupted writer"
    );
    Ok(())
}

#[test]
fn reopening_rejects_an_unexpected_non_file_store_entry() -> TestResult {
    let layout = StoreLayout::new()?;
    {
        let _store = ArtifactStore::open(&layout.root)?;
    }
    fs::create_dir(objects_directory(&layout.root).join("unexpected-directory"))?;

    let error = ArtifactStore::open(&layout.root)
        .expect_err("unexpected directories must not bypass bounded store accounting");
    assert_eq!(error.code(), ArtifactErrorCode::Corrupt);
    Ok(())
}

#[test]
fn published_objects_are_owner_private_single_link_and_read_only() -> TestResult {
    let layout = StoreLayout::new()?;
    let store = ArtifactStore::open(&layout.root)?;
    let stored = store.put(PAYLOAD)?;
    let path = object_path(&layout.root, stored.id().as_str());
    let metadata = fs::metadata(&path)?;

    assert!(metadata.is_file());
    assert!(metadata.permissions().readonly());
    assert_owner_private_single_link(&metadata)?;
    assert_eq!(store.read_verified(stored.id())?.bytes(), PAYLOAD);

    make_broadly_readable(&path)?;
    let error = store
        .read_verified(stored.id())
        .expect_err("an object whose private metadata was weakened must be rejected");
    assert_eq!(error.code(), ArtifactErrorCode::Corrupt);
    Ok(())
}

#[test]
fn a_verified_object_survives_store_restart() -> TestResult {
    let layout = StoreLayout::new()?;
    let id = {
        let store = ArtifactStore::open(&layout.root)?;
        store.put(PAYLOAD)?.id().clone()
    };

    let reopened = ArtifactStore::open(&layout.root)?;
    let artifact = reopened.read_verified(&id)?;
    assert_eq!(artifact.id(), &id);
    assert_eq!(artifact.bytes(), PAYLOAD);
    Ok(())
}

#[test]
fn content_corruption_is_rejected_after_the_object_is_resealed() -> TestResult {
    let layout = StoreLayout::new()?;
    let store = ArtifactStore::open(&layout.root)?;
    let stored = store.put(PAYLOAD)?;
    let path = object_path(&layout.root, stored.id().as_str());
    let mut corrupt = PAYLOAD.to_vec();
    corrupt[0] ^= 1;

    set_object_writable(&path, true)?;
    fs::write(&path, &corrupt)?;
    set_object_writable(&path, false)?;

    let error = store
        .read_verified(stored.id())
        .expect_err("same-length bytes under the old digest must be rejected");
    assert_eq!(error.code(), ArtifactErrorCode::Corrupt);
    assert!(!format!("{error:?}\n{error}").contains(std::str::from_utf8(&corrupt)?));

    let error = store
        .put(PAYLOAD)
        .expect_err("publication must never replace a corrupt canonical object");
    assert_eq!(error.code(), ArtifactErrorCode::Corrupt);
    assert_eq!(fs::read(path)?, corrupt);
    Ok(())
}

#[test]
fn a_hard_link_to_an_object_invalidates_verified_reads() -> TestResult {
    let layout = StoreLayout::new()?;
    let store = ArtifactStore::open(&layout.root)?;
    let stored = store.put(PAYLOAD)?;
    let path = object_path(&layout.root, stored.id().as_str());
    let alias = layout.root.join("object-alias");
    fs::hard_link(&path, &alias)?;

    let error = store
        .read_verified(stored.id())
        .expect_err("a multiply linked object must be rejected");
    assert_eq!(error.code(), ArtifactErrorCode::Corrupt);

    fs::remove_file(alias)?;
    assert_eq!(store.read_verified(stored.id())?.bytes(), PAYLOAD);
    Ok(())
}

#[test]
fn linked_and_broadly_accessible_roots_are_rejected() -> TestResult {
    let layout = StoreLayout::new()?;
    let real = layout.private_directory("real")?;
    let alias = layout.root.join("linked-root");
    create_directory_redirect(&real, &alias)?;

    let error = ArtifactStore::open(&alias).expect_err("a linked root must fail closed");
    assert_eq!(error.code(), ArtifactErrorCode::InvalidRoot);
    remove_directory_redirect(&alias)?;

    let unsafe_root = layout.private_directory("unsafe")?;
    make_root_unsafe(&unsafe_root)?;
    let error =
        ArtifactStore::open(&unsafe_root).expect_err("a broadly accessible root must fail closed");
    assert_eq!(error.code(), ArtifactErrorCode::InvalidRoot);
    Ok(())
}

#[test]
fn debug_output_redacts_artifact_paths_and_payload_bytes() -> TestResult {
    let layout = StoreLayout::with_label(DEBUG_PATH_SENTINEL)?;
    let store = ArtifactStore::open(&layout.root)?;
    let stored = store.put(DEBUG_PAYLOAD_SENTINEL.as_bytes())?;

    for rendered in [format!("{store:?}"), format!("{stored:?}")] {
        assert!(!rendered.contains(DEBUG_PATH_SENTINEL));
        assert!(!rendered.contains(DEBUG_PAYLOAD_SENTINEL));
    }

    let path = object_path(&layout.root, stored.id().as_str());
    set_object_writable(&path, true)?;
    fs::write(&path, b"corrupt")?;
    set_object_writable(&path, false)?;
    let error = store
        .read_verified(stored.id())
        .expect_err("the corrupt fixture must return a sanitized error");
    let rendered = format!("{error:?}\n{error}");
    assert!(!rendered.contains(DEBUG_PATH_SENTINEL));
    assert!(!rendered.contains(DEBUG_PAYLOAD_SENTINEL));
    assert!(!rendered.contains(layout.root.to_string_lossy().as_ref()));
    Ok(())
}

fn object_path(root: &Path, id: &str) -> PathBuf {
    objects_directory(root).join(id)
}

fn objects_directory(root: &Path) -> PathBuf {
    root.join("objects").join("sha256")
}

fn temporary_object_names(root: &Path) -> std::io::Result<Vec<String>> {
    fs::read_dir(objects_directory(root))?
        .filter_map(|entry| match entry {
            Ok(entry)
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".tmp-")) =>
            {
                Some(Ok(entry.file_name().to_string_lossy().into_owned()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

#[cfg(unix)]
fn assert_owner_private_single_link(metadata: &fs::Metadata) -> TestResult {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    assert_eq!(metadata.nlink(), 1);
    Ok(())
}

#[cfg(windows)]
fn assert_owner_private_single_link(metadata: &fs::Metadata) -> TestResult {
    use std::os::windows::fs::MetadataExt;

    assert_ne!(
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY,
        0
    );
    Ok(())
}

#[cfg(unix)]
fn set_object_writable(path: &Path, writable: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if writable { 0o600 } else { 0o400 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn make_file_owner_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn make_file_owner_private(path: &Path) -> std::io::Result<()> {
    make_owner_only_acl(path, false)
}

#[cfg(windows)]
fn set_object_writable(path: &Path, writable: bool) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(!writable);
    fs::set_permissions(path, permissions)
}

#[cfg(unix)]
fn make_broadly_readable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o444))
}

#[cfg(windows)]
fn make_broadly_readable(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/grant", "*S-1-1-0:R"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the Windows object fixture could not install a broad DACL",
        ))
    }
}

#[cfg(unix)]
fn create_directory_redirect(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_directory_redirect(target: &Path, link: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the Windows junction fixture could not be created",
        ))
    }
}

#[cfg(unix)]
fn remove_directory_redirect(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

#[cfg(windows)]
fn remove_directory_redirect(path: &Path) -> std::io::Result<()> {
    fs::remove_dir(path)
}

#[cfg(unix)]
fn make_root_unsafe(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o777))
}

#[cfg(windows)]
fn make_root_unsafe(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the Windows root fixture could not install a broad DACL",
        ))
    }
}

#[cfg(unix)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    make_owner_only_acl(path, true)
}

#[cfg(windows)]
fn make_owner_only_acl(path: &Path, inheritable: bool) -> std::io::Result<()> {
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
    let grant = if inheritable {
        format!("{numeric_identity}:(OI)(CI)F")
    } else {
        format!("{numeric_identity}:F")
    };
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

#[cfg(windows)]
fn clear_readonly_files(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            clear_readonly_files(&path);
        } else if let Ok(metadata) = entry.metadata() {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}
