use std::error::Error;

use carl::security::{SecretFilter, SecretRule};

type TestResult = Result<(), Box<dyn Error>>;

const OPENAI_SENTINEL: &str = "sk-proj-0123456789abcdefghijklmnop";
const GITHUB_SENTINEL: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
const SLACK_SENTINEL: &str = "xoxb-0123456789abcdefghijklmnopqrstuv";
const ASSIGNMENT_SENTINEL: &str = "private-value-0123456789";
const CONNECTION_SENTINEL: &str = "postgres://carl:private-password@localhost/carl";

#[test]
fn high_confidence_secret_shapes_are_classified() {
    let cases = [
        (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n".to_vec(),
            SecretRule::PrivateKey,
        ),
        (
            OPENAI_SENTINEL.as_bytes().to_vec(),
            SecretRule::ProviderToken,
        ),
        (
            GITHUB_SENTINEL.as_bytes().to_vec(),
            SecretRule::ProviderToken,
        ),
        (
            b"github_pat_0123456789abcdefghijklmnopqrstuv".to_vec(),
            SecretRule::ProviderToken,
        ),
        (
            SLACK_SENTINEL.as_bytes().to_vec(),
            SecretRule::ProviderToken,
        ),
        (
            b"const KEY: &str = \"AKIA0123456789ABCDEF\";".to_vec(),
            SecretRule::ProviderToken,
        ),
        (
            format!("api_key = \"{ASSIGNMENT_SENTINEL}\"").into_bytes(),
            SecretRule::CredentialAssignment,
        ),
        (
            format!("{{\"refresh_token\":\"{ASSIGNMENT_SENTINEL}\"}}").into_bytes(),
            SecretRule::CredentialAssignment,
        ),
        (
            format!("password: \"{ASSIGNMENT_SENTINEL}\"").into_bytes(),
            SecretRule::CredentialAssignment,
        ),
        (
            format!("database_url: \"{CONNECTION_SENTINEL}\"").into_bytes(),
            SecretRule::ConnectionString,
        ),
    ];

    for (contents, expected) in cases {
        let finding = SecretFilter
            .inspect(&contents)
            .expect_err("the fixture contains a high-confidence secret");
        assert_eq!(finding.rule(), expected);
    }
}

#[test]
fn findings_never_retain_or_render_matched_bytes() {
    for sentinel in [
        OPENAI_SENTINEL,
        GITHUB_SENTINEL,
        SLACK_SENTINEL,
        ASSIGNMENT_SENTINEL,
        CONNECTION_SENTINEL,
    ] {
        let input = if sentinel == ASSIGNMENT_SENTINEL {
            format!("secret = \"{sentinel}\"")
        } else {
            sentinel.to_owned()
        };
        let finding = SecretFilter
            .inspect(input.as_bytes())
            .expect_err("the fixture contains a secret");

        assert!(!format!("{finding:?}").contains(sentinel));
        assert!(!finding.to_string().contains(sentinel));
        assert_eq!(
            std::mem::size_of_val(&finding),
            std::mem::size_of::<SecretRule>()
        );
    }
}

#[test]
fn ordinary_source_and_placeholders_are_accepted() -> TestResult {
    let accepted = [
        "let token_count = input.len();",
        "let sha = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";",
        "let id = \"11111111-1111-4111-8111-111111111111\";",
        "api_key = \"${OPENAI_API_KEY}\"",
        "token = \"example\"",
        "secret = \"placeholder\"",
        "password = \"changeme\"",
        "cookie = \"\"",
        "database_url = \"postgres://localhost/carl\"",
        "pub enum AuthenticationRequired {}",
    ];

    for contents in accepted {
        SecretFilter.inspect(contents.as_bytes())?;
    }
    Ok(())
}

#[test]
fn non_utf8_and_unbounded_inputs_fail_without_content() {
    let non_utf8 = SecretFilter
        .inspect(&[0xff, 0xfe])
        .expect_err("non-UTF-8 content must be rejected");
    assert_eq!(non_utf8.rule(), SecretRule::NonUtf8);

    let oversized = SecretFilter
        .inspect(&vec![b'a'; 1_048_577])
        .expect_err("unbounded content must be rejected");
    assert_eq!(oversized.rule(), SecretRule::InputLimit);
    assert!(!format!("{oversized:?}").contains(&"a".repeat(32)));
}
