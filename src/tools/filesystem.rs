use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{NativeToolError, NativeToolErrorCode, invalid_arguments, io_error};
use crate::security::SecretFilter;

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_LIST_ENTRIES: usize = 2_000;
const MAX_SEARCH_MATCHES: usize = 2_000;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadArguments {
    path: String,
    start_line: Option<usize>,
    end_line: Option<usize>,
}

pub(super) struct ReadAction {
    path: PathBuf,
    relative: String,
    digest: [u8; 32],
    start_line: Option<usize>,
    end_line: Option<usize>,
}

impl ReadAction {
    pub(super) fn prepare(root: &Path, args: ReadArguments) -> Result<Self, NativeToolError> {
        if args.start_line == Some(0)
            || args.end_line == Some(0)
            || matches!((args.start_line, args.end_line), (Some(start), Some(end)) if start > end)
        {
            return Err(invalid_arguments());
        }
        let (path, relative) = regular_file(root, &args.path)?;
        let bytes = bounded_read(&path)?;
        Ok(Self {
            path,
            relative,
            digest: Sha256::digest(&bytes).into(),
            start_line: args.start_line,
            end_line: args.end_line,
        })
    }

    pub(super) fn summary(&self) -> String {
        format!("read {}", self.relative)
    }

    pub(super) async fn execute(
        self,
        cancellation: CancellationToken,
    ) -> Result<Value, NativeToolError> {
        ensure_not_cancelled(&cancellation)?;
        let bytes = bounded_read(&self.path)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != self.digest {
            return Err(NativeToolError::new(NativeToolErrorCode::WorkspaceChanged));
        }
        SecretFilter
            .inspect(&bytes)
            .map_err(|_| NativeToolError::new(NativeToolErrorCode::SecretDetected))?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid_arguments())?;
        let selected = select_lines(text, self.start_line, self.end_line);
        Ok(json!({"path":self.relative,"text":selected}))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListArguments {
    path: String,
}

pub(super) struct ListAction {
    path: PathBuf,
    relative: String,
}

impl ListAction {
    pub(super) fn prepare(root: &Path, args: ListArguments) -> Result<Self, NativeToolError> {
        let (path, relative) = directory(root, &args.path)?;
        Ok(Self { path, relative })
    }

    pub(super) fn summary(&self) -> String {
        format!("list {}", self.relative)
    }

    pub(super) async fn execute(
        self,
        cancellation: CancellationToken,
    ) -> Result<Value, NativeToolError> {
        ensure_not_cancelled(&cancellation)?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.path).map_err(|_| io_error())? {
            ensure_not_cancelled(&cancellation)?;
            let entry = entry.map_err(|_| io_error())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_arguments())?;
            if name == ".git" {
                continue;
            }
            let kind = entry.file_type().map_err(|_| io_error())?;
            if kind.is_symlink() {
                return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
            }
            let kind = if kind.is_file() {
                "file"
            } else if kind.is_dir() {
                "directory"
            } else {
                return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
            };
            let path = if self.relative == "." {
                name
            } else {
                format!("{}/{}", self.relative, name)
            };
            entries.push(json!({"path":path,"kind":kind}));
            if entries.len() > MAX_LIST_ENTRIES {
                return Err(NativeToolError::new(NativeToolErrorCode::OutputTooLarge));
            }
        }
        entries.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
        let output = json!({"entries":entries});
        ensure_output_bound(&output)?;
        Ok(output)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SearchArguments {
    query: String,
    path: String,
    #[serde(default)]
    regex: bool,
}

pub(super) struct SearchAction {
    root: PathBuf,
    relative: String,
    matcher: Matcher,
}

enum Matcher {
    Literal(String),
    Regex(Regex),
}

impl SearchAction {
    pub(super) fn prepare(root: &Path, args: SearchArguments) -> Result<Self, NativeToolError> {
        if args.query.is_empty() || args.query.len() > 4096 {
            return Err(invalid_arguments());
        }
        let (path, relative) = existing(root, &args.path)?;
        let matcher = if args.regex {
            Matcher::Regex(Regex::new(&args.query).map_err(|_| invalid_arguments())?)
        } else {
            Matcher::Literal(args.query)
        };
        Ok(Self {
            root: path,
            relative,
            matcher,
        })
    }

    pub(super) fn summary(&self) -> String {
        format!("search {}", self.relative)
    }

    pub(super) async fn execute(
        self,
        cancellation: CancellationToken,
    ) -> Result<Value, NativeToolError> {
        let mut stack = vec![(self.root, self.relative)];
        let mut matches = Vec::new();
        while let Some((path, relative)) = stack.pop() {
            ensure_not_cancelled(&cancellation)?;
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| io_error())?;
            if metadata.file_type().is_symlink() {
                return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
            }
            if metadata.is_dir() {
                let mut children = std::fs::read_dir(path)
                    .map_err(|_| io_error())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| io_error())?;
                children.sort_by_key(std::fs::DirEntry::file_name);
                for child in children.into_iter().rev() {
                    let name = child
                        .file_name()
                        .into_string()
                        .map_err(|_| invalid_arguments())?;
                    if name == ".git" {
                        continue;
                    }
                    let child_relative = if relative == "." {
                        name
                    } else {
                        format!("{relative}/{name}")
                    };
                    stack.push((child.path(), child_relative));
                }
                continue;
            }
            if !metadata.is_file() {
                return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
            }
            let bytes = bounded_read(&path)?;
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            if SecretFilter.inspect(&bytes).is_err() {
                continue;
            }
            for (index, line) in text.lines().enumerate() {
                let found = match &self.matcher {
                    Matcher::Literal(query) => line
                        .match_indices(query)
                        .map(|(column, _)| column)
                        .collect::<Vec<_>>(),
                    Matcher::Regex(regex) => {
                        regex.find_iter(line).map(|found| found.start()).collect()
                    }
                };
                for column in found {
                    matches.push(
                        json!({"path":relative,"line":index + 1,"column":column + 1,"text":line}),
                    );
                    if matches.len() > MAX_SEARCH_MATCHES {
                        return Err(NativeToolError::new(NativeToolErrorCode::OutputTooLarge));
                    }
                }
            }
        }
        let output = json!({"matches":matches});
        ensure_output_bound(&output)?;
        Ok(output)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchArguments {
    changes: Vec<PatchChange>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchChange {
    path: String,
    find: String,
    replace: String,
}

pub(super) struct PatchAction {
    changes: Vec<PreparedChange>,
}

struct PreparedChange {
    path: PathBuf,
    relative: String,
    before_digest: [u8; 32],
    after: Vec<u8>,
}

impl PatchAction {
    pub(super) fn prepare(root: &Path, args: PatchArguments) -> Result<Self, NativeToolError> {
        if args.changes.is_empty() || args.changes.len() > 128 {
            return Err(invalid_arguments());
        }
        let mut unique = HashSet::new();
        let mut changes = Vec::new();
        for change in args.changes {
            if change.find.is_empty() || !unique.insert(change.path.clone()) {
                return Err(invalid_arguments());
            }
            let (path, relative) = regular_file(root, &change.path)?;
            let before = bounded_read(&path)?;
            let text = std::str::from_utf8(&before).map_err(|_| invalid_arguments())?;
            if text.matches(&change.find).count() != 1 {
                return Err(invalid_arguments());
            }
            let after = text.replacen(&change.find, &change.replace, 1).into_bytes();
            if after.len() > MAX_FILE_BYTES || SecretFilter.inspect(&after).is_err() {
                return Err(NativeToolError::new(NativeToolErrorCode::SecretDetected));
            }
            changes.push(PreparedChange {
                path,
                relative,
                before_digest: Sha256::digest(&before).into(),
                after,
            });
        }
        Ok(Self { changes })
    }

    pub(super) fn summary(&self) -> String {
        format!("edit {} file(s)", self.changes.len())
    }

    pub(super) async fn execute(
        self,
        cancellation: CancellationToken,
    ) -> Result<Value, NativeToolError> {
        ensure_not_cancelled(&cancellation)?;
        for change in &self.changes {
            let current = bounded_read(&change.path)?;
            if <[u8; 32]>::from(Sha256::digest(current)) != change.before_digest {
                return Err(NativeToolError::new(NativeToolErrorCode::WorkspaceChanged));
            }
        }
        let mut temporary = Vec::new();
        for change in &self.changes {
            let parent = change.path.parent().ok_or_else(io_error)?;
            let temp = parent.join(format!(".carl-edit-{}", Uuid::new_v4()));
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            use std::io::Write as _;
            let mut file = options.open(&temp).map_err(|_| io_error())?;
            file.write_all(&change.after).map_err(|_| io_error())?;
            file.sync_all().map_err(|_| io_error())?;
            temporary.push(temp);
        }
        ensure_not_cancelled(&cancellation)?;
        for (change, temp) in self.changes.iter().zip(&temporary) {
            if let Err(error) = std::fs::rename(temp, &change.path) {
                for remaining in &temporary {
                    let _ = std::fs::remove_file(remaining);
                }
                let _ = error;
                return Err(io_error());
            }
        }
        Ok(
            json!({"changed_files":self.changes.len(),"paths":self.changes.iter().map(|change| &change.relative).collect::<Vec<_>>() }),
        )
    }
}

fn existing(root: &Path, relative: &str) -> Result<(PathBuf, String), NativeToolError> {
    let normalized = validate_relative(relative)?;
    let candidate = root.join(if normalized == "." { "" } else { &normalized });
    reject_symlink_components(root, &normalized)?;
    let canonical = std::fs::canonicalize(&candidate).map_err(|_| io_error())?;
    if !canonical.starts_with(root) {
        return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
    }
    Ok((canonical, normalized))
}

fn regular_file(root: &Path, relative: &str) -> Result<(PathBuf, String), NativeToolError> {
    let result = existing(root, relative)?;
    let metadata = std::fs::metadata(&result.0).map_err(|_| io_error())?;
    if !metadata.is_file() || has_multiple_links(&metadata) {
        return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
    }
    Ok(result)
}

fn directory(root: &Path, relative: &str) -> Result<(PathBuf, String), NativeToolError> {
    let result = existing(root, relative)?;
    if !std::fs::metadata(&result.0)
        .map_err(|_| io_error())?
        .is_dir()
    {
        return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
    }
    Ok(result)
}

fn validate_relative(value: &str) -> Result<String, NativeToolError> {
    if value == "." {
        return Ok(value.to_owned());
    }
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() || value.as_bytes().contains(&0) {
        return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| NativeToolError::new(NativeToolErrorCode::UnsafePath))?;
                if value == ".git" || value.chars().any(char::is_control) {
                    return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
                }
                parts.push(value);
            }
            _ => return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath)),
        }
    }
    if parts.is_empty() {
        return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
    }
    Ok(parts.join("/"))
}

fn reject_symlink_components(root: &Path, relative: &str) -> Result<(), NativeToolError> {
    let mut current = root.to_path_buf();
    if relative == "." {
        return Ok(());
    }
    for part in relative.split('/') {
        current.push(part);
        if std::fs::symlink_metadata(&current)
            .map_err(|_| io_error())?
            .file_type()
            .is_symlink()
        {
            return Err(NativeToolError::new(NativeToolErrorCode::UnsafePath));
        }
    }
    Ok(())
}

fn bounded_read(path: &Path) -> Result<Vec<u8>, NativeToolError> {
    let metadata = std::fs::metadata(path).map_err(|_| io_error())?;
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(NativeToolError::new(NativeToolErrorCode::OutputTooLarge));
    }
    let bytes = std::fs::read(path).map_err(|_| io_error())?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(NativeToolError::new(NativeToolErrorCode::OutputTooLarge));
    }
    Ok(bytes)
}

fn select_lines(text: &str, start: Option<usize>, end: Option<usize>) -> String {
    if start.is_none() && end.is_none() {
        return text.to_owned();
    }
    let start = start.unwrap_or(1);
    let end = end.unwrap_or(usize::MAX);
    let mut output = text
        .lines()
        .enumerate()
        .filter(|(index, _)| (*index + 1) >= start && (*index + 1) <= end)
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    if !output.is_empty() && text.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<(), NativeToolError> {
    if cancellation.is_cancelled() {
        Err(NativeToolError::new(NativeToolErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn ensure_output_bound(value: &Value) -> Result<(), NativeToolError> {
    if serde_json::to_vec(value).map_err(|_| io_error())?.len() > MAX_OUTPUT_BYTES {
        Err(NativeToolError::new(NativeToolErrorCode::OutputTooLarge))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn has_multiple_links(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.nlink() != 1
}

#[cfg(not(unix))]
fn has_multiple_links(_: &std::fs::Metadata) -> bool {
    false
}
