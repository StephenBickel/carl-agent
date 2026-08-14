use std::fs;
use std::path::Path;

#[test]
fn tui_dependency_policy_avoids_unmaintained_paste_and_allows_reviewed_licenses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let lock = fs::read_to_string(root.join("Cargo.lock")).unwrap();
    let deny = fs::read_to_string(root.join("deny.toml")).unwrap();

    assert!(
        manifest.contains(
            "ratatui = { version = \"0.30\", default-features = false, features = [\"crossterm\"] }"
        ) && manifest.contains("crossterm = { version = \"0.29\", features = [\"event-stream\"] }"),
        "the reviewed TUI dependencies must stay on the compatible maintained pair"
    );
    assert!(
        !lock.contains("\nname = \"paste\"\n"),
        "the unmaintained paste crate must not return to the locked graph"
    );
    assert!(deny.contains("\"ISC\""));
    assert!(deny.contains("\"CDLA-Permissive-2.0\""));
    assert!(deny.contains("\"BSD-3-Clause\""));
}
