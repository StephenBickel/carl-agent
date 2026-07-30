use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::artifacts::ArtifactStore;
use carl::security::{SecretFilter, SecretRule};
use carl::staging::{
    ProposalErrorCode, ProposalLimits, ProposalOutcome, SanitizedStageBuilder, StageErrorCode,
    StageLimits,
};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BEFORE: &[u8] = b"pub fn answer() -> u32 { 41 }\n";
const AFTER: &[u8] = b"pub fn answer() -> u32 { 42 }\n";
const BEFORE_HASH: &str = "039fbcec96985c10017e474fb7369cd56387158fdb896cb3f597f311b9cb3bd7";
const AFTER_HASH: &str = "5e0a6af76181b77032ef291474aab99538433cb86eb2b8ad88f3c0cfb2577a51";
const BASELINE_MANIFEST_DIGEST: &str =
    "ea74248d072e53098bb607ec892dee1b1c59ac117fb7ef8fcab40d10ecb66d36";
const PROPOSAL_ARTIFACT_ID: &str =
    "763ca7e546b9250a17059f9d900b8b9473a57cb302f7db2c4b0a4af4d3a40fd2";
const SECRET_SENTINEL: &str = "sk-proj-0123456789abcdefghijklmnop";

struct ProposalLayout {
    root: PathBuf,
    source: PathBuf,
    stages: PathBuf,
    artifacts: PathBuf,
}

impl ProposalLayout {
    fn new() -> TestResult<Self> {
        #[cfg(unix)]
        let temporary_root = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let temporary_root = std::env::temp_dir();

        let root = temporary_root.join(format!("carl-proposal-{}", Uuid::new_v4()));
        let source = root.join("source");
        let stages = root.join("stages");
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&source)?;
        fs::create_dir_all(&stages)?;
        fs::create_dir_all(&artifacts)?;
        make_owner_only(&root)?;
        make_owner_only(&source)?;
        make_owner_only(&stages)?;
        make_owner_only(&artifacts)?;
        Ok(Self {
            root,
            source,
            stages,
            artifacts,
        })
    }

    fn write_source(&self, relative: &str, contents: &[u8]) -> TestResult {
        let path = self.source.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }
}

impl Drop for ProposalLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn preparation_seals_a_disjoint_baseline_and_returns_only_the_work_stage() -> TestResult {
    let layout = ProposalLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stage = builder(&layout)?.prepare(&store)?;

    assert_eq!(
        stage.manifest().digest().to_string(),
        BASELINE_MANIFEST_DIGEST
    );
    assert_eq!(stage.baseline_manifest(), stage.manifest());
    assert_eq!(fs::read(stage.path().join("src/lib.rs"))?, BEFORE);
    assert!(!stage.path().starts_with(fs::canonicalize(&layout.source)?));
    assert!(
        !stage
            .path()
            .starts_with(fs::canonicalize(&layout.artifacts)?)
    );
    assert!(!layout.artifacts.starts_with(stage.path()));

    let stored_baseline = snapshot_files(&layout.artifacts)?;
    assert!(
        !stored_baseline.is_empty(),
        "preparation must persist the sealed baseline outside the mutable stage"
    );

    let workspace_debug = format!("{:?}", stage.execution_workspace()?);
    assert!(!workspace_debug.contains(layout.source.to_string_lossy().as_ref()));
    assert!(!workspace_debug.contains(layout.artifacts.to_string_lossy().as_ref()));

    fs::write(stage.path().join("src/lib.rs"), AFTER)?;
    assert_eq!(fs::read(layout.source.join("src/lib.rs"))?, BEFORE);
    assert_eq!(
        stage.baseline_manifest().digest().to_string(),
        BASELINE_MANIFEST_DIGEST
    );

    let stage_path = stage.path().to_path_buf();
    stage.cleanup()?;
    assert!(!stage_path.exists());
    assert_eq!(snapshot_files(&layout.artifacts)?, stored_baseline);
    Ok(())
}

#[test]
fn one_existing_utf8_replacement_produces_the_literal_inert_artifact() -> TestResult {
    let layout = ProposalLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stage = builder(&layout)?.prepare(&store)?;
    fs::write(stage.path().join("src/lib.rs"), AFTER)?;

    let outcome = stage.inspect_proposal(&store, ProposalLimits::new(1_024)?, SecretFilter)?;
    let proposal = match outcome {
        ProposalOutcome::ExactReplacement(proposal) => proposal,
        ProposalOutcome::NoChanges => panic!("the changed file must produce a proposal"),
    };

    assert_eq!(proposal.artifact_id().as_str(), PROPOSAL_ARTIFACT_ID);
    assert_eq!(
        proposal.baseline_manifest_digest().to_string(),
        BASELINE_MANIFEST_DIGEST
    );
    assert_eq!(proposal.path(), "src/lib.rs");
    assert_eq!(proposal.expected_live_hash().to_string(), BEFORE_HASH);
    assert_eq!(proposal.before_hash().to_string(), BEFORE_HASH);
    assert_eq!(proposal.after_hash().to_string(), AFTER_HASH);
    assert_eq!(proposal.payload_hash().to_string(), AFTER_HASH);
    assert_eq!(proposal.payload(), AFTER);
    assert_eq!(fs::read(layout.source.join("src/lib.rs"))?, BEFORE);

    let artifact_files = snapshot_files(&layout.artifacts)?;
    assert!(
        artifact_files
            .keys()
            .any(|path| path.to_string_lossy().contains(PROPOSAL_ARTIFACT_ID)),
        "the exact content-addressed proposal envelope must be durable"
    );
    Ok(())
}

#[test]
fn an_unchanged_stage_returns_no_changes_without_writing_a_proposal() -> TestResult {
    let layout = ProposalLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stage = builder(&layout)?.prepare(&store)?;
    let before = snapshot_files(&layout.artifacts)?;

    assert!(matches!(
        stage.inspect_proposal(&store, ProposalLimits::new(1_024)?, SecretFilter)?,
        ProposalOutcome::NoChanges
    ));
    assert_eq!(snapshot_files(&layout.artifacts)?, before);
    Ok(())
}

#[test]
fn structural_changes_are_rejected_deterministically() -> TestResult {
    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::CreatedFile,
        "new.txt",
        None,
        |_, stage| {
            fs::write(stage.join("new.txt"), b"new\n")?;
            Ok(())
        },
    )?;
    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::DeletedFile,
        "src/lib.rs",
        None,
        |_, stage| {
            fs::remove_file(stage.join("src/lib.rs"))?;
            Ok(())
        },
    )?;
    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::RenamedFile,
        "src/lib.rs",
        None,
        |_, stage| {
            fs::rename(stage.join("src/lib.rs"), stage.join("src/answer.rs"))?;
            Ok(())
        },
    )?;
    assert_rejected(
        &[("a.txt", b"one\n"), ("b.txt", b"two\n")],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::MultipleFiles,
        "b.txt",
        None,
        |_, stage| {
            fs::write(stage.join("a.txt"), b"ONE\n")?;
            fs::write(stage.join("b.txt"), b"TWO\n")?;
            Ok(())
        },
    )
}

#[test]
fn redirected_and_hard_linked_paths_are_rejected() -> TestResult {
    let layout = ProposalLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stage = builder(&layout)?.prepare(&store)?;
    let before = snapshot_files(&layout.artifacts)?;
    let outside = layout.root.join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("lib.rs"), AFTER)?;
    fs::remove_dir_all(stage.path().join("src"))?;
    create_directory_redirect(&outside, &stage.path().join("src"))?;

    let error = stage
        .inspect_proposal(&store, ProposalLimits::new(1_024)?, SecretFilter)
        .expect_err("a redirected path must not become a proposal");
    assert_eq!(error.code(), ProposalErrorCode::RedirectedPath);
    assert_eq!(error.path(), Some("src"));
    assert_eq!(error.secret_rule(), None);
    assert_eq!(snapshot_files(&layout.artifacts)?, before);

    remove_directory_redirect(&stage.path().join("src"))?;
    drop(stage);

    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::HardLink,
        "src/lib.rs",
        None,
        |layout, stage| {
            fs::hard_link(
                stage.join("src/lib.rs"),
                layout.root.join("outside-hard-link"),
            )?;
            Ok(())
        },
    )
}

#[test]
fn invalid_payloads_and_protected_paths_are_rejected() -> TestResult {
    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::NonUtf8,
        "src/lib.rs",
        None,
        |_, stage| {
            fs::write(stage.join("src/lib.rs"), [0xff, 0xfe, 0xfd])?;
            Ok(())
        },
    )?;
    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::ProtectedPath,
        ".git",
        None,
        |_, stage| {
            fs::create_dir(stage.join(".git"))?;
            fs::write(stage.join(".git/config"), b"[core]\n")?;
            Ok(())
        },
    )?;
    assert_rejected(
        &[("a.txt", b"1234")],
        ProposalLimits::new(4)?,
        ProposalErrorCode::LimitExceeded,
        "a.txt",
        None,
        |_, stage| {
            fs::write(stage.join("a.txt"), b"12345")?;
            Ok(())
        },
    )
}

#[test]
fn metadata_only_changes_and_generated_secrets_are_rejected() -> TestResult {
    #[cfg(unix)]
    let metadata_path = "src";
    #[cfg(not(unix))]
    let metadata_path = "src/lib.rs";

    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::MetadataChanged,
        metadata_path,
        None,
        |_, stage| {
            #[cfg(unix)]
            let path = stage.join("src");
            #[cfg(not(unix))]
            let path = stage.join("src/lib.rs");
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_readonly(true);
            fs::set_permissions(path, permissions)?;
            Ok(())
        },
    )?;

    let secret_payload = format!("const TOKEN: &str = \"{SECRET_SENTINEL}\";\n");
    assert_rejected(
        &[("src/lib.rs", BEFORE)],
        ProposalLimits::new(1_024)?,
        ProposalErrorCode::SecretDetected,
        "src/lib.rs",
        Some(SecretRule::ProviderToken),
        |_, stage| {
            fs::write(stage.join("src/lib.rs"), secret_payload.as_bytes())?;
            Ok(())
        },
    )
}

#[test]
fn artifact_storage_must_be_disjoint_from_source_and_stage_roots() -> TestResult {
    let layout = ProposalLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;

    let source_artifacts = layout.source.join("artifact-root");
    fs::create_dir(&source_artifacts)?;
    make_owner_only(&source_artifacts)?;
    assert_overlap_rejected(&layout, &source_artifacts)?;

    let nested_source = layout.artifacts.join("nested-source");
    fs::create_dir(&nested_source)?;
    make_owner_only(&nested_source)?;
    fs::write(nested_source.join("lib.rs"), BEFORE)?;
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stages_before = snapshot_files(&layout.stages)?;
    let error = SanitizedStageBuilder::open(
        &nested_source,
        &layout.stages,
        StageLimits::new(100, 64 * 1_024, 1024 * 1_024)?,
        SecretFilter,
    )?
    .prepare(&store)
    .expect_err("a source nested in the artifact root must fail before staging");
    assert_eq!(error.code(), StageErrorCode::InvalidRoot);
    assert_eq!(snapshot_files(&layout.stages)?, stages_before);

    assert_overlap_rejected(&layout, &layout.stages)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn cleanup_never_changes_permissions_through_an_external_hard_link() -> TestResult {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let layout = ProposalLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stage = builder(&layout)?.prepare(&store)?;
    let staged_file = stage.path().join("src/lib.rs");
    fs::set_permissions(&staged_file, fs::Permissions::from_mode(0o400))?;
    let outside = layout.root.join("outside-hard-link");
    fs::hard_link(&staged_file, &outside)?;
    let outside_mode = fs::metadata(&outside)?.mode() & 0o777;

    let error = stage
        .inspect_proposal(&store, ProposalLimits::new(1_024)?, SecretFilter)
        .expect_err("a hard-linked stage file must be rejected");
    assert_eq!(error.code(), ProposalErrorCode::HardLink);
    drop(stage);

    assert_eq!(fs::metadata(&outside)?.mode() & 0o777, outside_mode);
    Ok(())
}

fn assert_overlap_rejected(layout: &ProposalLayout, artifact_root: &Path) -> TestResult {
    let store = ArtifactStore::open(artifact_root)?;
    let artifacts_before = snapshot_files(artifact_root)?;
    let stages_before = snapshot_files(&layout.stages)?;
    let error = builder(layout)?
        .prepare(&store)
        .expect_err("overlapping artifact storage must fail before staging");
    assert_eq!(error.code(), StageErrorCode::InvalidRoot);
    assert_eq!(snapshot_files(artifact_root)?, artifacts_before);
    assert_eq!(snapshot_files(&layout.stages)?, stages_before);
    Ok(())
}

fn assert_rejected(
    initial: &[(&str, &[u8])],
    limits: ProposalLimits,
    expected_code: ProposalErrorCode,
    expected_path: &str,
    expected_secret_rule: Option<SecretRule>,
    mutate: impl FnOnce(&ProposalLayout, &Path) -> TestResult,
) -> TestResult {
    let layout = ProposalLayout::new()?;
    for (path, contents) in initial {
        layout.write_source(path, contents)?;
    }
    let source_before = initial
        .iter()
        .map(|(path, contents)| ((*path).to_owned(), contents.to_vec()))
        .collect::<BTreeMap<_, _>>();
    let store = ArtifactStore::open(&layout.artifacts)?;
    let stage = builder(&layout)?.prepare(&store)?;
    let stage_path = stage.path().to_path_buf();
    let artifacts_before = snapshot_files(&layout.artifacts)?;

    mutate(&layout, stage.path())?;
    let error = stage
        .inspect_proposal(&store, limits, SecretFilter)
        .expect_err("the unsafe stage mutation must be rejected");

    assert_eq!(error.code(), expected_code);
    assert_eq!(error.path(), Some(expected_path));
    assert_eq!(error.secret_rule(), expected_secret_rule);
    assert_eq!(snapshot_files(&layout.artifacts)?, artifacts_before);
    for (path, expected) in source_before {
        assert_eq!(fs::read(layout.source.join(path))?, expected);
    }
    let rendered = format!("{error:?}\n{error}");
    assert!(!rendered.contains(SECRET_SENTINEL));
    drop(stage);
    assert!(
        !stage_path.exists(),
        "a rejected stage must not remain after its guard is dropped"
    );
    Ok(())
}

fn builder(layout: &ProposalLayout) -> Result<SanitizedStageBuilder, carl::staging::StageError> {
    SanitizedStageBuilder::open(
        &layout.source,
        &layout.stages,
        StageLimits::new(100, 64 * 1_024, 1024 * 1_024)?,
        SecretFilter,
    )
}

fn snapshot_files(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                visit(root, &path, files)?;
            } else if file_type.is_file() {
                files.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
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

#[cfg(windows)]
#[cfg(unix)]
fn remove_directory_redirect(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

#[cfg(windows)]
fn remove_directory_redirect(path: &Path) -> std::io::Result<()> {
    fs::remove_dir(path)
}

#[cfg(unix)]
fn remove_directory_redirect(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
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
