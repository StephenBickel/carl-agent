use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::artifacts::ArtifactStore;
use carl::security::{SecretFilter, SecretRule};
use carl::staging::{
    SanitizedStage, SanitizedStageBuilder, StageContainment, StageErrorCode, StageExclusionReason,
    StageLimits,
};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MANIFEST_DIGEST: &str =
    "61230977ab9e218134b491a0574b29ea1d53507e0ed8b653202d4515fc7e3d32";
const SECRET_SENTINEL: &str = "sk-proj-0123456789abcdefghijklmnop";

struct StageLayout {
    root: PathBuf,
    source: PathBuf,
    stages: PathBuf,
    artifacts: PathBuf,
}

impl StageLayout {
    fn new() -> TestResult<Self> {
        #[cfg(unix)]
        let temporary_root = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let temporary_root = std::env::temp_dir();
        let root = temporary_root.join(format!("carl-stage-{}", Uuid::new_v4()));
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

    fn write(&self, relative: &str, contents: &[u8]) -> TestResult {
        let path = self.source.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }
}

impl Drop for StageLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn stage_is_owner_only_deterministic_and_disposable() -> TestResult {
    let first = StageLayout::new()?;
    first.write("src/lib.rs", b"pub fn answer() -> u32 { 42 }\n")?;
    first.write("README.md", b"hello\n")?;
    #[cfg(unix)]
    let source_mode = permissions(&first.source.join("README.md"))?;

    let stage = prepare(&first, StageLimits::new(10, 1_024, 4_096)?)?;
    assert_ne!(stage.path(), first.source);
    assert!(stage.path().starts_with(fs::canonicalize(&first.stages)?));
    assert_eq!(
        stage.containment(),
        StageContainment::CurrentUserPrivateVerified
    );
    assert_eq!(
        stage.manifest().digest().to_string(),
        EXPECTED_MANIFEST_DIGEST
    );
    assert_eq!(stage.manifest().total_bytes(), 36);
    assert_eq!(
        stage
            .manifest()
            .entries()
            .iter()
            .map(|entry| (entry.path(), entry.bytes()))
            .collect::<Vec<_>>(),
        vec![("README.md", 6), ("src/lib.rs", 30)]
    );
    assert_eq!(
        stage.manifest().entries()[0].content_digest().to_string(),
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    );
    assert_eq!(
        stage.manifest().entries()[1].content_digest().to_string(),
        "5e0a6af76181b77032ef291474aab99538433cb86eb2b8ad88f3c0cfb2577a51"
    );
    assert_eq!(
        fs::read(stage.path().join("README.md"))?,
        b"hello\n".as_slice()
    );
    assert_eq!(
        fs::read(stage.path().join("src/lib.rs"))?,
        b"pub fn answer() -> u32 { 42 }\n".as_slice()
    );
    #[cfg(unix)]
    {
        assert_owner_only(stage.path())?;
        assert_owner_only(&stage.path().join("README.md"))?;
        assert_eq!(permissions(&first.source.join("README.md"))?, source_mode);
    }
    let workspace_debug = format!("{:?}", stage.execution_workspace()?);
    assert!(!workspace_debug.contains(first.source.to_string_lossy().as_ref()));

    let stage_path = stage.path().to_path_buf();
    drop(stage);
    assert!(!stage_path.exists());

    let second = StageLayout::new()?;
    second.write("README.md", b"hello\n")?;
    second.write("src/lib.rs", b"pub fn answer() -> u32 { 42 }\n")?;
    let stage = prepare(&second, StageLimits::new(10, 1_024, 4_096)?)?;
    assert_eq!(
        stage.manifest().digest().to_string(),
        EXPECTED_MANIFEST_DIGEST
    );
    Ok(())
}

#[test]
fn protected_and_unsupported_entries_never_reach_the_stage() -> TestResult {
    let layout = StageLayout::new()?;
    layout.write("src/lib.rs", b"pub fn safe() {}\n")?;
    layout.write(".git/config", b"[core]\n")?;
    layout.write(".carl/state.json", b"{}\n")?;
    layout.write(".codex/config.toml", b"model = \"private\"\n")?;
    layout.write(".grok/settings.json", b"{}\n")?;
    layout.write(".claude/settings.json", b"{}\n")?;
    layout.write(".cursor/rules", b"private\n")?;
    layout.write(".mcp.json", b"{}\n")?;
    layout.write(".env", b"SAFE_PLACEHOLDER=example\n")?;
    layout.write(".env.local", b"SAFE_PLACEHOLDER=example\n")?;
    layout.write("AGENTS.md", b"private instructions\n")?;
    layout.write("CLAUDE.md", b"private instructions\n")?;
    layout.write("GEMINI.md", b"private instructions\n")?;
    layout.write(".cursorrules", b"private instructions\n")?;
    layout.write(".github/copilot-instructions.md", b"private instructions\n")?;
    layout.write("hooks/pre-commit", b"#!/bin/sh\n")?;
    layout.write("plugins/plugin.json", b"{}\n")?;
    layout.write("skills/private/SKILL.md", b"private\n")?;
    layout.write("commands/deploy.md", b"private\n")?;
    layout.write("private.pem", b"placeholder\n")?;
    layout.write("binary.bin", &[0xff, 0xfe, 0xfd])?;
    layout.write("hard-source.txt", b"hard link\n")?;
    fs::hard_link(
        layout.source.join("hard-source.txt"),
        layout.source.join("hard-copy.txt"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        layout.source.join("src/lib.rs"),
        layout.source.join("link.rs"),
    )?;
    #[cfg(windows)]
    {
        let outside = layout.root.join("outside");
        fs::create_dir(&outside)?;
        fs::write(outside.join("must-not-copy.txt"), b"outside sentinel\n")?;
        let junction = layout.source.join("outside-junction");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "the Windows junction fixture must be created"
        );
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let fifo = layout.source.join("events.fifo");
        let fifo = CString::new(fifo.as_os_str().as_bytes())?;
        // SAFETY: `fifo` is a valid NUL-terminated path and the mode contains only
        // permission bits. The test removes the FIFO with its temporary directory.
        if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(unix)]
    let _socket = std::os::unix::net::UnixListener::bind(layout.source.join("events.socket"))?;

    let stage = prepare(&layout, StageLimits::new(100, 4_096, 64 * 1_024)?)?;
    assert_eq!(
        stage
            .manifest()
            .entries()
            .iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        vec!["src/lib.rs"]
    );
    let exclusions: BTreeMap<_, _> = stage
        .exclusions()
        .iter()
        .map(|entry| (entry.path(), entry.reason()))
        .collect();
    assert_eq!(
        exclusions.get(".git").copied(),
        Some(StageExclusionReason::ProtectedPath)
    );
    assert_eq!(
        exclusions.get(".env").copied(),
        Some(StageExclusionReason::SensitiveFilename)
    );
    assert_eq!(
        exclusions.get("AGENTS.md").copied(),
        Some(StageExclusionReason::CompatibilityInstruction)
    );
    assert_eq!(
        exclusions.get("private.pem").copied(),
        Some(StageExclusionReason::SensitiveFilename)
    );
    assert_eq!(
        exclusions.get("binary.bin").copied(),
        Some(StageExclusionReason::NonUtf8)
    );
    assert_eq!(
        exclusions.get("hard-source.txt").copied(),
        Some(StageExclusionReason::HardLink)
    );
    #[cfg(unix)]
    {
        assert_eq!(
            exclusions.get("link.rs").copied(),
            Some(StageExclusionReason::Symlink)
        );
        assert_eq!(
            exclusions.get("events.fifo").copied(),
            Some(StageExclusionReason::SpecialFile)
        );
        assert_eq!(
            exclusions.get("events.socket").copied(),
            Some(StageExclusionReason::SpecialFile)
        );
    }
    #[cfg(windows)]
    assert_eq!(
        exclusions.get("outside-junction").copied(),
        Some(StageExclusionReason::Symlink)
    );
    Ok(())
}

#[test]
fn protected_source_roots_and_git_redirect_files_are_rejected_or_excluded() -> TestResult {
    let layout = StageLayout::new()?;
    let protected_source = layout.root.join(".codex");
    fs::create_dir(&protected_source)?;
    fs::write(
        protected_source.join("config.toml"),
        b"private provider config\n",
    )?;
    assert_eq!(
        SanitizedStageBuilder::open(
            &protected_source,
            &layout.stages,
            StageLimits::new(10, 1_024, 4_096)?,
            SecretFilter,
        )
        .expect_err("a protected directory cannot become the traversal root")
        .code(),
        StageErrorCode::InvalidRoot
    );

    layout.write("src/lib.rs", b"pub fn safe() {}\n")?;
    layout.write(
        ".git",
        b"gitdir: /absolute/live/repository/worktrees/private\n",
    )?;
    let stage = prepare(&layout, StageLimits::new(10, 1_024, 4_096)?)?;
    assert!(!stage.path().join(".git").exists());
    assert_eq!(
        stage
            .exclusions()
            .iter()
            .find(|entry| entry.path() == ".git")
            .map(|entry| entry.reason()),
        Some(StageExclusionReason::ProtectedPath)
    );
    Ok(())
}

#[test]
fn a_secret_rejects_the_entire_stage_with_path_only_diagnostics() -> TestResult {
    let layout = StageLayout::new()?;
    layout.write(
        "src/config.rs",
        format!("const TOKEN: &str = \"{SECRET_SENTINEL}\";\n").as_bytes(),
    )?;
    let error = prepare(&layout, StageLimits::new(10, 4_096, 16 * 1_024)?)
        .expect_err("a secret-bearing source file must reject the stage");

    assert_eq!(error.code(), StageErrorCode::SecretDetected);
    assert_eq!(error.path(), Some("src/config.rs"));
    assert_eq!(error.secret_rule(), Some(SecretRule::ProviderToken));
    assert!(!format!("{error:?}").contains(SECRET_SENTINEL));
    assert!(!error.to_string().contains(SECRET_SENTINEL));
    assert_eq!(fs::read_dir(&layout.stages)?.count(), 0);
    Ok(())
}

#[test]
fn stage_limits_fail_on_the_first_file_or_byte_beyond_the_boundary() -> TestResult {
    let exact = StageLayout::new()?;
    exact.write("four.txt", b"1234")?;
    exact.write("two.txt", b"12")?;
    let exact_stage = prepare(&exact, StageLimits::new(2, 4, 6)?)?;
    assert_eq!(exact_stage.manifest().entries().len(), 2);
    assert_eq!(exact_stage.manifest().total_bytes(), 6);

    let file_count = StageLayout::new()?;
    file_count.write("one.txt", b"1")?;
    file_count.write("two.txt", b"2")?;
    assert_eq!(
        prepare(&file_count, StageLimits::new(1, 10, 10)?)
            .expect_err("second file exceeds count")
            .code(),
        StageErrorCode::LimitExceeded
    );

    let entry_count = StageLayout::new()?;
    fs::create_dir(entry_count.source.join("first-directory"))?;
    fs::create_dir(entry_count.source.join("second-directory"))?;
    assert_eq!(
        prepare(&entry_count, StageLimits::new(1, 10, 10)?)
            .expect_err("directories consume the same bounded entry budget")
            .code(),
        StageErrorCode::LimitExceeded
    );

    let file_bytes = StageLayout::new()?;
    file_bytes.write("six.txt", b"123456")?;
    assert_eq!(
        prepare(&file_bytes, StageLimits::new(1, 5, 10)?)
            .expect_err("sixth byte exceeds per-file limit")
            .code(),
        StageErrorCode::LimitExceeded
    );

    let total_bytes = StageLayout::new()?;
    total_bytes.write("four.txt", b"1234")?;
    total_bytes.write("three.txt", b"123")?;
    assert_eq!(
        prepare(&total_bytes, StageLimits::new(2, 4, 6)?)
            .expect_err("seventh aggregate byte exceeds limit")
            .code(),
        StageErrorCode::LimitExceeded
    );
    Ok(())
}

#[test]
fn source_and_stage_roots_must_be_absolute_disjoint_directories() -> TestResult {
    let layout = StageLayout::new()?;
    assert_eq!(
        SanitizedStageBuilder::open(
            Path::new("relative-source"),
            &layout.stages,
            StageLimits::new(1, 1, 1)?,
            SecretFilter,
        )
        .expect_err("relative source must fail")
        .code(),
        StageErrorCode::InvalidRoot
    );
    assert_eq!(
        SanitizedStageBuilder::open(
            &layout.source,
            Path::new("relative-stages"),
            StageLimits::new(1, 1, 1)?,
            SecretFilter,
        )
        .expect_err("relative stage parent must fail")
        .code(),
        StageErrorCode::InvalidRoot
    );
    let nested = layout.source.join("stages");
    fs::create_dir(&nested)?;
    assert_eq!(
        SanitizedStageBuilder::open(
            &layout.source,
            &nested,
            StageLimits::new(1, 1, 1)?,
            SecretFilter,
        )
        .expect_err("stage root inside source must fail")
        .code(),
        StageErrorCode::InvalidRoot
    );
    #[cfg(unix)]
    {
        let unsafe_parent = layout.root.join("unsafe-stages");
        fs::create_dir(&unsafe_parent)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
        assert_eq!(
            SanitizedStageBuilder::open(
                &layout.source,
                &unsafe_parent,
                StageLimits::new(1, 1, 1)?,
                SecretFilter,
            )
            .expect_err("a group/world-accessible stage parent must fail")
            .code(),
            StageErrorCode::InvalidRoot
        );
    }
    #[cfg(windows)]
    {
        let unsafe_parent = layout.root.join("unsafe-stages");
        fs::create_dir(&unsafe_parent)?;
        let status = std::process::Command::new("icacls")
            .arg(&unsafe_parent)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "the Windows broad-DACL fixture must be created"
        );
        assert_eq!(
            SanitizedStageBuilder::open(
                &layout.source,
                &unsafe_parent,
                StageLimits::new(1, 1, 1)?,
                SecretFilter,
            )
            .expect_err("a broadly writable Windows stage parent must fail")
            .code(),
            StageErrorCode::InvalidRoot
        );

        let real_parent = layout.root.join("real-stages");
        fs::create_dir(&real_parent)?;
        let junction_parent = layout.root.join("junction-stages");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction_parent)
            .arg(&real_parent)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "the Windows stage-parent junction fixture must be created"
        );
        assert_eq!(
            SanitizedStageBuilder::open(
                &layout.source,
                &junction_parent,
                StageLimits::new(1, 1, 1)?,
                SecretFilter,
            )
            .expect_err("a Windows stage-parent junction must fail")
            .code(),
            StageErrorCode::InvalidRoot
        );

        let real_source = layout.root.join("real-source");
        fs::create_dir(&real_source)?;
        fs::write(real_source.join("README.md"), b"junction source\n")?;
        let junction_source = layout.root.join("junction-source");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction_source)
            .arg(&real_source)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "the Windows source-root junction fixture must be created"
        );
        assert_eq!(
            SanitizedStageBuilder::open(
                &junction_source,
                &layout.stages,
                StageLimits::new(10, 1_024, 4_096)?,
                SecretFilter,
            )
            .expect_err("a Windows source-root junction must fail")
            .code(),
            StageErrorCode::InvalidRoot
        );
    }
    Ok(())
}

#[test]
fn stage_path_is_anchored_to_the_canonical_held_parent() -> TestResult {
    #[cfg(unix)]
    {
        let layout = StageLayout::new()?;
        layout.write("README.md", b"hello\n")?;
        let alias = layout
            .root
            .with_file_name(format!("carl-stage-alias-{}", Uuid::new_v4()));
        std::os::unix::fs::symlink(&layout.root, &alias)?;
        let aliased_stages = alias.join("stages");

        let store = ArtifactStore::open(&layout.artifacts)?;
        let stage = SanitizedStageBuilder::open(
            &layout.source,
            &aliased_stages,
            StageLimits::new(10, 1_024, 4_096)?,
            SecretFilter,
        )?
        .prepare(&store)?;
        assert!(
            stage.path().starts_with(fs::canonicalize(&layout.stages)?),
            "the execution path must use the canonical held parent"
        );
        assert!(
            !stage.path().starts_with(&alias),
            "an ambient alias must not survive into the execution path"
        );
        drop(stage);
        fs::remove_file(alias)?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn execution_workspace_rejects_a_named_stage_replacement() -> TestResult {
    let layout = StageLayout::new()?;
    layout.write("README.md", b"hello\n")?;
    let stage = prepare(&layout, StageLimits::new(10, 1_024, 4_096)?)?;
    let original = stage.path().to_path_buf();
    let moved = layout
        .stages
        .join(format!("moved-stage-{}", Uuid::new_v4()));
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    make_owner_only(&original)?;

    assert!(
        stage.execution_workspace().is_err(),
        "the ambient stage name must still identify the held work directory"
    );

    fs::remove_dir(&original)?;
    fs::rename(&moved, &original)?;
    drop(stage);
    assert!(!original.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn cleanup_removes_a_stage_renamed_within_its_held_parent() -> TestResult {
    let layout = StageLayout::new()?;
    layout.write("README.md", b"must be deleted\n")?;
    let stage = prepare(&layout, StageLimits::new(10, 1_024, 4_096)?)?;
    let original = stage.path().to_path_buf();
    let moved = layout
        .stages
        .join(format!("moved-stage-{}", Uuid::new_v4()));
    fs::rename(&original, &moved)?;

    stage.cleanup()?;

    assert!(!original.exists());
    assert!(!moved.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn cleanup_never_deletes_a_replacement_at_the_original_stage_name() -> TestResult {
    let layout = StageLayout::new()?;
    layout.write("README.md", b"held stage\n")?;
    let stage = prepare(&layout, StageLimits::new(10, 1_024, 4_096)?)?;
    let original = stage.path().to_path_buf();
    let moved = layout
        .stages
        .join(format!("moved-stage-{}", Uuid::new_v4()));
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    make_owner_only(&original)?;
    fs::write(original.join("replacement-sentinel"), b"must survive\n")?;

    stage.cleanup()?;

    assert!(!moved.exists());
    assert_eq!(
        fs::read(original.join("replacement-sentinel"))?,
        b"must survive\n"
    );
    Ok(())
}

#[test]
fn cleanup_is_iterative_for_agent_created_deep_trees() -> TestResult {
    let layout = StageLayout::new()?;
    layout.write("README.md", b"held stage\n")?;
    let stage = prepare(&layout, StageLimits::new(10, 1_024, 4_096)?)?;
    let stage_path = stage.path().to_path_buf();
    let mut nested = stage_path.clone();
    for depth in 0..96 {
        nested.push(format!("d{depth}"));
        fs::create_dir(&nested)?;
    }
    fs::write(nested.join("deep-sentinel"), b"must be deleted\n")?;

    stage.cleanup()?;

    assert!(!stage_path.exists());
    Ok(())
}

fn builder(
    layout: &StageLayout,
    limits: StageLimits,
) -> Result<SanitizedStageBuilder, carl::staging::StageError> {
    SanitizedStageBuilder::open(&layout.source, &layout.stages, limits, SecretFilter)
}

fn prepare(
    layout: &StageLayout,
    limits: StageLimits,
) -> Result<SanitizedStage, carl::staging::StageError> {
    let store =
        ArtifactStore::open(&layout.artifacts).expect("the private artifact fixture must open");
    builder(layout, limits)?.prepare(&store)
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

#[cfg(unix)]
fn assert_owner_only(path: &Path) -> TestResult {
    assert_eq!(permissions(path)? & 0o077, 0);
    Ok(())
}

#[cfg(unix)]
fn permissions(path: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}
