//! Private, content-addressed storage for immutable Carl artifacts.
//!
//! Artifact bytes are never an authority to mutate a live workspace. Callers
//! receive identifiers and verified bytes, while the backing paths stay opaque.

mod store;

use std::fmt;

pub use crate::runtime::subscription::ArtifactId;
pub use store::{ArtifactStore, StoredArtifact};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactErrorCode {
    InvalidRoot,
    LimitExceeded,
    Corrupt,
    Io,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ArtifactError {
    code: ArtifactErrorCode,
}

impl ArtifactError {
    pub(crate) const fn new(code: ArtifactErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> ArtifactErrorCode {
        self.code
    }
}

impl fmt::Debug for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            ArtifactErrorCode::InvalidRoot => {
                formatter.write_str("The artifact root is not private and trustworthy.")
            }
            ArtifactErrorCode::LimitExceeded => {
                formatter.write_str("The artifact exceeds Carl's storage limit.")
            }
            ArtifactErrorCode::Corrupt => {
                formatter.write_str("A content-addressed artifact failed verification.")
            }
            ArtifactErrorCode::Io => formatter.write_str("The artifact store is unavailable."),
        }
    }
}

impl std::error::Error for ArtifactError {}
