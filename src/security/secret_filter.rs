use std::fmt;

const MAX_SCAN_BYTES: usize = 1024 * 1024;
const MIN_ASSIGNED_SECRET_BYTES: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRule {
    PrivateKey,
    ProviderToken,
    CredentialAssignment,
    ConnectionString,
    NonUtf8,
    InputLimit,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecretFinding {
    rule: SecretRule,
}

impl SecretFinding {
    const fn new(rule: SecretRule) -> Self {
        Self { rule }
    }

    #[must_use]
    pub const fn rule(self) -> SecretRule {
        self.rule
    }
}

impl fmt::Debug for SecretFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFinding")
            .field("rule", &self.rule)
            .finish()
    }
}

impl fmt::Display for SecretFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("High-confidence secret material was detected.")
    }
}

impl std::error::Error for SecretFinding {}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecretFilter;

impl SecretFilter {
    pub fn inspect(self, input: &[u8]) -> Result<(), SecretFinding> {
        if input.len() > MAX_SCAN_BYTES {
            return Err(SecretFinding::new(SecretRule::InputLimit));
        }
        let input =
            std::str::from_utf8(input).map_err(|_| SecretFinding::new(SecretRule::NonUtf8))?;
        if contains_private_key(input) {
            return Err(SecretFinding::new(SecretRule::PrivateKey));
        }
        if contains_provider_token(input.as_bytes()) {
            return Err(SecretFinding::new(SecretRule::ProviderToken));
        }
        for line in input.lines() {
            if contains_credentialed_connection(line) {
                return Err(SecretFinding::new(SecretRule::ConnectionString));
            }
            if contains_secret_assignment(line) {
                return Err(SecretFinding::new(SecretRule::CredentialAssignment));
            }
        }
        Ok(())
    }
}

fn contains_private_key(input: &str) -> bool {
    input.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ") && line.ends_with(" PRIVATE KEY-----") && line.len() <= 96
    })
}

fn contains_provider_token(input: &[u8]) -> bool {
    contains_prefixed_token(input, b"sk-", 20)
        || contains_prefixed_token(input, b"ghp_", 24)
        || contains_prefixed_token(input, b"github_pat_", 24)
        || contains_prefixed_token(input, b"xoxb-", 24)
        || contains_prefixed_token(input, b"xoxa-", 24)
        || contains_prefixed_token(input, b"xoxp-", 24)
        || contains_prefixed_token(input, b"xoxr-", 24)
        || contains_prefixed_token(input, b"xoxs-", 24)
        || contains_aws_access_key(input)
}

fn contains_prefixed_token(input: &[u8], prefix: &[u8], minimum_total: usize) -> bool {
    input
        .windows(prefix.len())
        .enumerate()
        .any(|(index, window)| {
            window == prefix
                && input[index..]
                    .iter()
                    .take_while(|byte| token_byte(**byte))
                    .count()
                    >= minimum_total
        })
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn contains_aws_access_key(input: &[u8]) -> bool {
    input.windows(20).any(|candidate| {
        candidate.starts_with(b"AKIA")
            && candidate[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn contains_credentialed_connection(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    for scheme in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mongodb://",
        "redis://",
    ] {
        let Some(start) = lowered.find(scheme) else {
            continue;
        };
        let authority = &line[start + scheme.len()..];
        let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
        let Some((credentials, _host)) = authority.rsplit_once('@') else {
            continue;
        };
        let Some((user, password)) = credentials.split_once(':') else {
            continue;
        };
        if !user.is_empty() && !password.is_empty() {
            return true;
        }
    }
    false
}

fn contains_secret_assignment(line: &str) -> bool {
    let Some((key, value)) = split_assignment(line) else {
        return false;
    };
    let key = key
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\'' | '{' | '}' | ','))
        .to_ascii_lowercase()
        .replace('-', "_");
    let sensitive_key = ["api_key", "apikey", "token", "secret", "password", "cookie"]
        .iter()
        .any(|needle| key.contains(needle));
    if !sensitive_key {
        return false;
    }

    let value = value.trim().trim_end_matches([',', '}', ';']).trim();
    let Some(value) = quoted_value(value) else {
        return false;
    };
    value.len() >= MIN_ASSIGNED_SECRET_BYTES && !is_placeholder(value)
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let equals = line.find('=');
    let colon = line.find(':');
    let delimiter = match (equals, colon) {
        (Some(equals), Some(colon)) => equals.min(colon),
        (Some(equals), None) => equals,
        (None, Some(colon)) => colon,
        (None, None) => return None,
    };
    Some((&line[..delimiter], &line[delimiter + 1..]))
}

fn quoted_value(value: &str) -> Option<&str> {
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'"' | b'\'') || value.as_bytes().last().copied()? != quote {
        return None;
    }
    value.get(1..value.len().checked_sub(1)?)
}

fn is_placeholder(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    lowered.is_empty()
        || matches!(
            lowered.as_str(),
            "example" | "placeholder" | "changeme" | "change_me" | "replace_me"
        )
        || lowered.starts_with("${")
        || lowered.starts_with("$env:")
        || lowered.starts_with("env(")
        || lowered.starts_with("process.env.")
}
