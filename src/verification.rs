use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::artifacts::{ArtifactId, ArtifactStore};
use crate::error::CarlError;
use crate::policy::Sha256Digest;
use crate::runtime::subscription::{RunId, VerificationId};
use crate::security::SecretFilter;
use crate::sidecar::{
    BoundedProcessLimits, BoundedProcessOutcome, ClosedEnvironment, TrustedExecutable,
    TrustedExecutableAttestation, run_bounded_process,
};
use crate::staging::{
    CandidateFile, ProposalLimits, SourcePreconditionRef, StageManifestEntry,
    VerificationCandidate, canonical_manifest_bytes, canonical_proposal_envelope,
    canonical_source_preconditions,
};
use crate::storage::{
    RuntimeStore, SubscriptionRunBaselineRecord, SubscriptionRunProposalRecord,
    VerificationCompletionRecord,
};
use tokio_util::sync::CancellationToken;

const SPECIFICATION_DOMAIN: &[u8] = b"carl.verification-spec.v1\0";
const ATTESTATION_DOMAIN: &[u8] = b"carl.verification-executable.v1\0";
const ARGUMENTS_DOMAIN: &[u8] = b"carl.verification-argv.v1\0";
const REQUEST_DOMAIN: &[u8] = b"carl.verification-request.v1\0";
const RESULT_DOMAIN: &[u8] = b"carl.verification-result.v1\0";
const DIRECTORY_MANIFEST_DOMAIN: &[u8] = b"carl.baseline-directories.v1\0";
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 4 * 1024;
const MAX_ARGUMENT_TOTAL_BYTES: usize = 32 * 1024;
const MAX_DIRECTORY_COUNT: usize = 100_000;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_AGGREGATE_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXECUTABLE_IDENTITY_BYTES: usize = 128;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationEnvironmentProfile {
    CleanV1,
}

impl VerificationEnvironmentProfile {
    const fn tag(self) -> u8 {
        match self {
            Self::CleanV1 => 0,
        }
    }

    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::CleanV1 => "credential_free_v1",
        }
    }

    pub(crate) fn from_storage_str(value: &str) -> Result<Self, VerificationError> {
        match value {
            "credential_free_v1" => Ok(Self::CleanV1),
            _ => Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationLimits {
    execution_timeout: Duration,
    max_output_bytes: usize,
    graceful_shutdown_timeout: Duration,
    forced_shutdown_timeout: Duration,
    poll_interval: Duration,
}

impl VerificationLimits {
    pub fn new(
        execution_timeout: Duration,
        max_output_bytes: usize,
        graceful_shutdown_timeout: Duration,
        forced_shutdown_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, VerificationError> {
        BoundedProcessLimits::new(
            execution_timeout,
            max_output_bytes,
            graceful_shutdown_timeout,
            forced_shutdown_timeout,
            poll_interval,
        )
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidLimits))?;
        Ok(Self {
            execution_timeout,
            max_output_bytes,
            graceful_shutdown_timeout,
            forced_shutdown_timeout,
            poll_interval,
        })
    }

    #[must_use]
    pub const fn execution_timeout(self) -> Duration {
        self.execution_timeout
    }

    #[must_use]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }

    #[must_use]
    pub const fn graceful_shutdown_timeout(self) -> Duration {
        self.graceful_shutdown_timeout
    }

    #[must_use]
    pub const fn forced_shutdown_timeout(self) -> Duration {
        self.forced_shutdown_timeout
    }

    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.poll_interval
    }

    fn as_process_limits(self) -> Result<BoundedProcessLimits, VerificationError> {
        BoundedProcessLimits::new(
            self.execution_timeout,
            self.max_output_bytes,
            self.graceful_shutdown_timeout,
            self.forced_shutdown_timeout,
            self.poll_interval,
        )
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidLimits))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationErrorCode {
    InvalidLimits,
    InvalidArguments,
    UnsafeExecutable,
    InvalidEvidence,
    ArtifactCorrupt,
    CandidateInvalid,
    ProcessFailed,
    Io,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerificationError {
    code: VerificationErrorCode,
}

impl VerificationError {
    const fn new(code: VerificationErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> VerificationErrorCode {
        self.code
    }
}

impl fmt::Debug for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            VerificationErrorCode::InvalidLimits => "Verification limits are invalid.",
            VerificationErrorCode::InvalidArguments => {
                "Verification arguments are invalid or contain sensitive material."
            }
            VerificationErrorCode::UnsafeExecutable => {
                "The verification executable is not safely bound."
            }
            VerificationErrorCode::InvalidEvidence => "Verification evidence is inconsistent.",
            VerificationErrorCode::ArtifactCorrupt => {
                "A sealed verification artifact failed validation."
            }
            VerificationErrorCode::CandidateInvalid => {
                "The reconstructed verification candidate is invalid."
            }
            VerificationErrorCode::ProcessFailed => "The verification process failed.",
            VerificationErrorCode::Io => "Verification could not complete safely.",
        })
    }
}

impl std::error::Error for VerificationError {}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct VerificationExecutableEvidence {
    canonical_path: String,
    metadata_risk_tag: String,
    platform_identity_evidence: Vec<u8>,
    byte_len: u64,
    content_sha256: Sha256Digest,
}

impl VerificationExecutableEvidence {
    fn from_attestation(attestation: &TrustedExecutableAttestation) -> Self {
        Self {
            canonical_path: attestation.canonical_path().to_owned(),
            metadata_risk_tag: attestation.metadata_risk_tag().to_owned(),
            platform_identity_evidence: attestation.platform_identity_evidence().to_vec(),
            byte_len: attestation.byte_len(),
            content_sha256: Sha256Digest::from_bytes(attestation.content_sha256()),
        }
    }

    pub(crate) fn rehydrate(
        canonical_path: String,
        metadata_risk_tag: String,
        platform_identity_evidence: Vec<u8>,
        byte_len: u64,
        content_sha256: Sha256Digest,
    ) -> Result<Self, VerificationError> {
        if canonical_path.is_empty()
            || canonical_path.len() > MAX_RELATIVE_PATH_BYTES
            || canonical_path.contains('\0')
            || !Path::new(&canonical_path).is_absolute()
            || !matches!(
                metadata_risk_tag.as_str(),
                "none" | "group_writable_install_directory"
            )
            || platform_identity_evidence.is_empty()
            || platform_identity_evidence.len() > MAX_EXECUTABLE_IDENTITY_BYTES
            || byte_len == 0
            || byte_len > MAX_EXECUTABLE_BYTES
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(Self {
            canonical_path,
            metadata_risk_tag,
            platform_identity_evidence,
            byte_len,
            content_sha256,
        })
    }

    pub(crate) fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    pub(crate) fn metadata_risk_tag(&self) -> &str {
        &self.metadata_risk_tag
    }

    pub(crate) fn platform_identity_evidence(&self) -> &[u8] {
        &self.platform_identity_evidence
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub(crate) const fn content_sha256(&self) -> Sha256Digest {
        self.content_sha256
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ATTESTATION_DOMAIN);
        append_text(&mut bytes, &self.canonical_path);
        bytes.extend_from_slice(&self.byte_len.to_be_bytes());
        bytes.extend_from_slice(self.content_sha256.as_bytes());
        append_text(&mut bytes, &self.metadata_risk_tag);
        append_bytes(&mut bytes, &self.platform_identity_evidence);
        bytes
    }
}

impl fmt::Debug for VerificationExecutableEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationExecutableEvidence")
            .field("canonical_path", &"<redacted>")
            .field("metadata_risk_tag", &self.metadata_risk_tag)
            .field("byte_len", &self.byte_len)
            .field("content_sha256", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct VerificationSpecEvidence {
    executable: VerificationExecutableEvidence,
    arguments: Vec<String>,
    environment_profile: VerificationEnvironmentProfile,
    limits: VerificationLimits,
    executable_attestation_digest: Sha256Digest,
    argument_vector_digest: Sha256Digest,
    specification_digest: Sha256Digest,
}

impl VerificationSpecEvidence {
    fn new(
        executable: VerificationExecutableEvidence,
        arguments: Vec<String>,
        environment_profile: VerificationEnvironmentProfile,
        limits: VerificationLimits,
    ) -> Result<Self, VerificationError> {
        validate_arguments(&arguments)?;
        limits.as_process_limits()?;
        let executable_attestation_digest = digest_bytes(&executable.canonical_bytes());
        let argument_vector_digest = digest_bytes(&canonical_arguments(&arguments));
        let specification_digest = digest_bytes(&canonical_specification(
            &executable,
            &arguments,
            environment_profile,
            limits,
        ));
        Ok(Self {
            executable,
            arguments,
            environment_profile,
            limits,
            executable_attestation_digest,
            argument_vector_digest,
            specification_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rehydrate(
        executable: VerificationExecutableEvidence,
        arguments: Vec<String>,
        environment_profile: VerificationEnvironmentProfile,
        limits: VerificationLimits,
        expected_executable_attestation_digest: Sha256Digest,
        expected_argument_vector_digest: Sha256Digest,
        expected_specification_digest: Sha256Digest,
    ) -> Result<Self, VerificationError> {
        let evidence = Self::new(executable, arguments, environment_profile, limits)?;
        if evidence.executable_attestation_digest != expected_executable_attestation_digest
            || evidence.argument_vector_digest != expected_argument_vector_digest
            || evidence.specification_digest != expected_specification_digest
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(evidence)
    }

    pub(crate) const fn executable(&self) -> &VerificationExecutableEvidence {
        &self.executable
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub(crate) const fn environment_profile(&self) -> VerificationEnvironmentProfile {
        self.environment_profile
    }

    pub(crate) const fn limits(&self) -> VerificationLimits {
        self.limits
    }

    pub(crate) const fn executable_attestation_digest(&self) -> Sha256Digest {
        self.executable_attestation_digest
    }

    pub(crate) const fn argument_vector_digest(&self) -> Sha256Digest {
        self.argument_vector_digest
    }

    pub(crate) const fn specification_digest(&self) -> Sha256Digest {
        self.specification_digest
    }

    pub(crate) fn executable_attestation_evidence(&self) -> String {
        hex_bytes(&self.executable.canonical_bytes())
    }

    pub(crate) fn argument_bytes(&self) -> usize {
        self.arguments.iter().map(String::len).sum()
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        canonical_specification(
            &self.executable,
            &self.arguments,
            self.environment_profile,
            self.limits,
        )
    }
}

#[derive(Clone)]
pub struct VerificationSpec {
    executable: TrustedExecutable,
    executable_attestation: TrustedExecutableAttestation,
    evidence: VerificationSpecEvidence,
}

impl VerificationSpec {
    pub fn new(
        executable: TrustedExecutable,
        arguments: Vec<String>,
        environment_profile: VerificationEnvironmentProfile,
        limits: VerificationLimits,
    ) -> Result<Self, VerificationError> {
        let executable_attestation = executable
            .verification_attestation()
            .map_err(|_| VerificationError::new(VerificationErrorCode::UnsafeExecutable))?;
        let evidence = VerificationSpecEvidence::new(
            VerificationExecutableEvidence::from_attestation(&executable_attestation),
            arguments,
            environment_profile,
            limits,
        )?;
        Ok(Self {
            executable,
            executable_attestation,
            evidence,
        })
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        self.evidence.arguments()
    }

    #[must_use]
    pub const fn environment_profile(&self) -> VerificationEnvironmentProfile {
        self.evidence.environment_profile()
    }

    #[must_use]
    pub const fn limits(&self) -> VerificationLimits {
        self.evidence.limits()
    }

    #[must_use]
    pub const fn specification_digest(&self) -> Sha256Digest {
        self.evidence.specification_digest()
    }

    pub(crate) const fn executable(&self) -> &TrustedExecutable {
        &self.executable
    }

    pub(crate) const fn executable_attestation(&self) -> &TrustedExecutableAttestation {
        &self.executable_attestation
    }

    pub(crate) const fn evidence(&self) -> &VerificationSpecEvidence {
        &self.evidence
    }

    pub(crate) const fn argument_vector_digest(&self) -> Sha256Digest {
        self.evidence.argument_vector_digest()
    }
}

impl fmt::Debug for VerificationSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationSpec")
            .field("executable", &"<redacted>")
            .field("argument_count", &self.arguments().len())
            .field("environment_profile", &self.environment_profile())
            .field("limits", &self.limits())
            .field("specification_digest", &self.specification_digest())
            .finish()
    }
}

#[derive(Clone)]
pub struct VerificationRequest {
    verification_id: VerificationId,
    run_id: RunId,
    baseline_manifest_artifact_id: ArtifactId,
    baseline_manifest_digest: Sha256Digest,
    source_preconditions_artifact_id: ArtifactId,
    source_preconditions_digest: Sha256Digest,
    baseline_directory_manifest_digest: Sha256Digest,
    proposal_artifact_id: ArtifactId,
    payload_artifact_id: ArtifactId,
    payload_digest: Sha256Digest,
    candidate_manifest_digest: Sha256Digest,
    specification: VerificationSpecEvidence,
    request_digest: Sha256Digest,
}

impl VerificationRequest {
    pub(crate) fn from_persisted(
        verification_id: VerificationId,
        run_id: RunId,
        baseline: &SubscriptionRunBaselineRecord,
        proposal: &SubscriptionRunProposalRecord,
        specification: &VerificationSpec,
    ) -> Result<Self, VerificationError> {
        validate_persisted_evidence(run_id, baseline, proposal)?;
        let mut request = Self {
            verification_id,
            run_id,
            baseline_manifest_artifact_id: baseline.manifest_artifact_id.clone(),
            baseline_manifest_digest: baseline.manifest_digest,
            source_preconditions_artifact_id: baseline.source_preconditions_artifact_id.clone(),
            source_preconditions_digest: baseline.source_preconditions_digest,
            baseline_directory_manifest_digest: baseline.directory_manifest_digest,
            proposal_artifact_id: proposal.proposal_artifact_id.clone(),
            payload_artifact_id: proposal.payload_artifact_id.clone(),
            payload_digest: proposal.payload_hash,
            candidate_manifest_digest: proposal.candidate_manifest_digest,
            specification: specification.evidence.clone(),
            request_digest: Sha256Digest::from_bytes([0; 32]),
        };
        request.request_digest = digest_bytes(&request.canonical_bytes());
        request.validate_recomputed()?;
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rehydrate(
        verification_id: VerificationId,
        run_id: RunId,
        baseline_manifest_artifact_id: ArtifactId,
        baseline_manifest_digest: Sha256Digest,
        source_preconditions_artifact_id: ArtifactId,
        source_preconditions_digest: Sha256Digest,
        baseline_directory_manifest_digest: Sha256Digest,
        proposal_artifact_id: ArtifactId,
        payload_artifact_id: ArtifactId,
        payload_digest: Sha256Digest,
        candidate_manifest_digest: Sha256Digest,
        specification: VerificationSpecEvidence,
        expected_request_digest: Sha256Digest,
    ) -> Result<Self, VerificationError> {
        if baseline_manifest_artifact_id.as_str() != baseline_manifest_digest.to_string()
            || source_preconditions_artifact_id.as_str() != source_preconditions_digest.to_string()
            || payload_artifact_id.as_str() != payload_digest.to_string()
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        let request = Self {
            verification_id,
            run_id,
            baseline_manifest_artifact_id,
            baseline_manifest_digest,
            source_preconditions_artifact_id,
            source_preconditions_digest,
            baseline_directory_manifest_digest,
            proposal_artifact_id,
            payload_artifact_id,
            payload_digest,
            candidate_manifest_digest,
            specification,
            request_digest: expected_request_digest,
        };
        request.validate_recomputed()?;
        Ok(request)
    }

    #[must_use]
    pub const fn verification_id(&self) -> VerificationId {
        self.verification_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn baseline_manifest_artifact_id(&self) -> &ArtifactId {
        &self.baseline_manifest_artifact_id
    }

    #[must_use]
    pub const fn baseline_manifest_digest(&self) -> Sha256Digest {
        self.baseline_manifest_digest
    }

    #[must_use]
    pub const fn source_preconditions_artifact_id(&self) -> &ArtifactId {
        &self.source_preconditions_artifact_id
    }

    #[must_use]
    pub const fn source_preconditions_digest(&self) -> Sha256Digest {
        self.source_preconditions_digest
    }

    #[must_use]
    pub const fn baseline_directory_manifest_digest(&self) -> Sha256Digest {
        self.baseline_directory_manifest_digest
    }

    #[must_use]
    pub const fn proposal_artifact_id(&self) -> &ArtifactId {
        &self.proposal_artifact_id
    }

    #[must_use]
    pub const fn payload_artifact_id(&self) -> &ArtifactId {
        &self.payload_artifact_id
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Sha256Digest {
        self.payload_digest
    }

    #[must_use]
    pub const fn candidate_manifest_digest(&self) -> Sha256Digest {
        self.candidate_manifest_digest
    }

    #[must_use]
    pub const fn specification_digest(&self) -> Sha256Digest {
        self.specification.specification_digest()
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    pub(crate) const fn specification(&self) -> &VerificationSpecEvidence {
        &self.specification
    }

    pub(crate) fn matches_live_specification(
        &self,
        specification: &VerificationSpec,
    ) -> Result<(), VerificationError> {
        if self.specification != specification.evidence {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_recomputed(&self) -> Result<(), VerificationError> {
        let canonical_specification = self.specification.canonical_bytes();
        if digest_bytes(&canonical_specification) != self.specification.specification_digest
            || digest_bytes(&self.canonical_bytes()) != self.request_digest
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REQUEST_DOMAIN);
        bytes.extend_from_slice(self.verification_id.as_uuid().as_bytes());
        bytes.extend_from_slice(self.run_id.as_uuid().as_bytes());
        append_text(&mut bytes, self.baseline_manifest_artifact_id.as_str());
        bytes.extend_from_slice(self.baseline_manifest_digest.as_bytes());
        append_text(&mut bytes, self.source_preconditions_artifact_id.as_str());
        bytes.extend_from_slice(self.source_preconditions_digest.as_bytes());
        bytes.extend_from_slice(self.baseline_directory_manifest_digest.as_bytes());
        append_text(&mut bytes, self.proposal_artifact_id.as_str());
        append_text(&mut bytes, self.payload_artifact_id.as_str());
        bytes.extend_from_slice(self.payload_digest.as_bytes());
        bytes.extend_from_slice(self.candidate_manifest_digest.as_bytes());
        let specification = self.specification.canonical_bytes();
        bytes.extend_from_slice(self.specification.specification_digest.as_bytes());
        append_bytes(&mut bytes, &specification);
        bytes
    }
}

impl fmt::Debug for VerificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationRequest")
            .field("verification_id", &self.verification_id)
            .field("run_id", &self.run_id)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Passed,
    NonZeroExit,
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
    ProcessFailed,
    CandidateMutated,
    OutputRejected,
}

impl VerificationOutcome {
    const fn tag(self) -> u8 {
        match self {
            Self::Passed => 0,
            Self::NonZeroExit => 1,
            Self::TimedOut => 2,
            Self::Cancelled => 3,
            Self::OutputLimitExceeded => 4,
            Self::ProcessFailed => 5,
            Self::CandidateMutated => 6,
            Self::OutputRejected => 7,
        }
    }

    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::NonZeroExit => "nonzero_exit",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::OutputLimitExceeded => "output_limit_exceeded",
            Self::ProcessFailed => "supervisor_failed",
            Self::CandidateMutated => "candidate_modified",
            Self::OutputRejected => "diagnostic_rejected",
        }
    }

    pub(crate) fn from_storage_str(value: &str) -> Result<Self, VerificationError> {
        match value {
            "passed" => Ok(Self::Passed),
            "nonzero_exit" => Ok(Self::NonZeroExit),
            "timed_out" => Ok(Self::TimedOut),
            "cancelled" => Ok(Self::Cancelled),
            "output_limit_exceeded" => Ok(Self::OutputLimitExceeded),
            "supervisor_failed" | "executable_rejected" => Ok(Self::ProcessFailed),
            "candidate_modified" => Ok(Self::CandidateMutated),
            "diagnostic_rejected" => Ok(Self::OutputRejected),
            _ => Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            )),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerificationDiagnostic {
    text: String,
    byte_length: u64,
    digest: Sha256Digest,
}

impl VerificationDiagnostic {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    fn clean(bytes: Vec<u8>) -> Result<Self, VerificationError> {
        SecretFilter
            .inspect(&bytes)
            .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
        if text.contains('\0') {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        let byte_length = u64::try_from(text.len())
            .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
        let digest = digest_bytes(text.as_bytes());
        Ok(Self {
            text,
            byte_length,
            digest,
        })
    }

    fn empty() -> Self {
        Self {
            text: String::new(),
            byte_length: 0,
            digest: digest_bytes(&[]),
        }
    }

    fn rehydrate(
        text: String,
        expected_byte_length: u64,
        expected_digest: Sha256Digest,
    ) -> Result<Self, VerificationError> {
        let diagnostic = Self::clean(text.into_bytes())?;
        if diagnostic.byte_length != expected_byte_length || diagnostic.digest != expected_digest {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(diagnostic)
    }
}

impl fmt::Debug for VerificationDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationDiagnostic")
            .field("byte_length", &self.byte_length)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerificationResult {
    verification_id: VerificationId,
    run_id: RunId,
    request_digest: Sha256Digest,
    expected_candidate_manifest_digest: Sha256Digest,
    expected_directory_manifest_digest: Sha256Digest,
    outcome: VerificationOutcome,
    exit_code: Option<i32>,
    observed_candidate_manifest_digest: Option<Sha256Digest>,
    observed_directory_manifest_digest: Option<Sha256Digest>,
    executable_attestation_evidence: String,
    executable_attestation_digest: Sha256Digest,
    stdout: VerificationDiagnostic,
    stderr: VerificationDiagnostic,
    duration: Duration,
    result_digest: Sha256Digest,
}

impl VerificationResult {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_observation(
        request: &VerificationRequest,
        outcome: VerificationOutcome,
        exit_code: Option<i32>,
        observed_candidate_manifest_digest: Option<Sha256Digest>,
        observed_directory_manifest_digest: Option<Sha256Digest>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<Self, VerificationError> {
        Self::from_execution_observation(
            request,
            outcome,
            exit_code,
            observed_candidate_manifest_digest,
            observed_directory_manifest_digest,
            stdout,
            stderr,
            Duration::ZERO,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_execution_observation(
        request: &VerificationRequest,
        outcome: VerificationOutcome,
        exit_code: Option<i32>,
        observed_candidate_manifest_digest: Option<Sha256Digest>,
        observed_directory_manifest_digest: Option<Sha256Digest>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
    ) -> Result<Self, VerificationError> {
        Self::build_execution_observation(
            request,
            outcome,
            exit_code,
            observed_candidate_manifest_digest,
            observed_directory_manifest_digest,
            stdout,
            stderr,
            duration,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_verified_execution(
        request: &VerificationRequest,
        specification: &VerificationSpec,
        receipt: &VerificationExecutionReceipt,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
    ) -> Result<Self, VerificationError> {
        receipt.validate(request, specification)?;
        Self::build_execution_observation(
            request,
            VerificationOutcome::Passed,
            Some(0),
            Some(receipt.candidate_manifest_digest),
            Some(receipt.directory_manifest_digest),
            stdout,
            stderr,
            duration,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_nonpassing_execution(
        request: &VerificationRequest,
        outcome: VerificationOutcome,
        exit_code: Option<i32>,
        observed_candidate_manifest_digest: Option<Sha256Digest>,
        observed_directory_manifest_digest: Option<Sha256Digest>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
    ) -> Result<Self, VerificationError> {
        if outcome == VerificationOutcome::Passed {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Self::build_execution_observation(
            request,
            outcome,
            exit_code,
            observed_candidate_manifest_digest,
            observed_directory_manifest_digest,
            stdout,
            stderr,
            duration,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_execution_observation(
        request: &VerificationRequest,
        mut outcome: VerificationOutcome,
        exit_code: Option<i32>,
        observed_candidate_manifest_digest: Option<Sha256Digest>,
        observed_directory_manifest_digest: Option<Sha256Digest>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
    ) -> Result<Self, VerificationError> {
        request.validate_recomputed()?;
        let combined_output = stdout
            .len()
            .checked_add(stderr.len())
            .ok_or_else(|| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
        let candidate_mutated = outcome == VerificationOutcome::CandidateMutated;
        let (stdout, stderr) = if outcome == VerificationOutcome::OutputLimitExceeded
            || combined_output > request.specification.limits.max_output_bytes
        {
            if !candidate_mutated {
                outcome = VerificationOutcome::OutputLimitExceeded;
            }
            (
                VerificationDiagnostic::empty(),
                VerificationDiagnostic::empty(),
            )
        } else {
            match (
                VerificationDiagnostic::clean(stdout),
                VerificationDiagnostic::clean(stderr),
            ) {
                (Ok(stdout), Ok(stderr)) => (stdout, stderr),
                _ => {
                    if !candidate_mutated {
                        outcome = VerificationOutcome::OutputRejected;
                    }
                    (
                        VerificationDiagnostic::empty(),
                        VerificationDiagnostic::empty(),
                    )
                }
            }
        };

        if (outcome == VerificationOutcome::Passed
            && (exit_code != Some(0)
                || observed_candidate_manifest_digest != Some(request.candidate_manifest_digest)
                || observed_directory_manifest_digest
                    != Some(request.baseline_directory_manifest_digest)))
            || (outcome == VerificationOutcome::NonZeroExit
                && exit_code.is_none_or(|code| code == 0))
            || !duration_within_result_limit(duration, request.specification.limits)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }

        let mut result = Self {
            verification_id: request.verification_id,
            run_id: request.run_id,
            request_digest: request.request_digest,
            expected_candidate_manifest_digest: request.candidate_manifest_digest,
            expected_directory_manifest_digest: request.baseline_directory_manifest_digest,
            outcome,
            exit_code,
            observed_candidate_manifest_digest,
            observed_directory_manifest_digest,
            executable_attestation_evidence: request
                .specification
                .executable_attestation_evidence(),
            executable_attestation_digest: request.specification.executable_attestation_digest(),
            stdout,
            stderr,
            duration,
            result_digest: Sha256Digest::from_bytes([0; 32]),
        };
        result.result_digest = digest_bytes(&result.canonical_bytes());
        result.validate_recomputed(request)?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rehydrate(
        _authority: &crate::storage::VerificationResultRehydrationAuthority,
        request: &VerificationRequest,
        outcome: VerificationOutcome,
        exit_code: Option<i32>,
        observed_candidate_manifest_digest: Option<Sha256Digest>,
        observed_directory_manifest_digest: Option<Sha256Digest>,
        executable_attestation_evidence: String,
        executable_attestation_digest: Sha256Digest,
        stdout_text: String,
        stdout_byte_length: u64,
        stdout_digest: Sha256Digest,
        stderr_text: String,
        stderr_byte_length: u64,
        stderr_digest: Sha256Digest,
        duration: Duration,
        expected_result_digest: Sha256Digest,
    ) -> Result<Self, VerificationError> {
        let result = Self {
            verification_id: request.verification_id,
            run_id: request.run_id,
            request_digest: request.request_digest,
            expected_candidate_manifest_digest: request.candidate_manifest_digest,
            expected_directory_manifest_digest: request.baseline_directory_manifest_digest,
            outcome,
            exit_code,
            observed_candidate_manifest_digest,
            observed_directory_manifest_digest,
            executable_attestation_evidence,
            executable_attestation_digest,
            stdout: VerificationDiagnostic::rehydrate(
                stdout_text,
                stdout_byte_length,
                stdout_digest,
            )?,
            stderr: VerificationDiagnostic::rehydrate(
                stderr_text,
                stderr_byte_length,
                stderr_digest,
            )?,
            duration,
            result_digest: expected_result_digest,
        };
        if outcome == VerificationOutcome::NonZeroExit && exit_code.is_none_or(|code| code == 0) {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        result.validate_recomputed(request)?;
        Ok(result)
    }

    #[must_use]
    pub const fn verification_id(&self) -> VerificationId {
        self.verification_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> VerificationOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    #[must_use]
    pub const fn observed_candidate_manifest_digest(&self) -> Option<Sha256Digest> {
        self.observed_candidate_manifest_digest
    }

    #[must_use]
    pub const fn observed_directory_manifest_digest(&self) -> Option<Sha256Digest> {
        self.observed_directory_manifest_digest
    }

    #[must_use]
    pub const fn expected_candidate_manifest_digest(&self) -> Sha256Digest {
        self.expected_candidate_manifest_digest
    }

    #[must_use]
    pub const fn expected_directory_manifest_digest(&self) -> Sha256Digest {
        self.expected_directory_manifest_digest
    }

    #[must_use]
    pub fn executable_attestation_evidence(&self) -> &str {
        &self.executable_attestation_evidence
    }

    #[must_use]
    pub const fn executable_attestation_digest(&self) -> Sha256Digest {
        self.executable_attestation_digest
    }

    #[must_use]
    pub const fn stdout(&self) -> &VerificationDiagnostic {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &VerificationDiagnostic {
        &self.stderr
    }

    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    #[must_use]
    pub const fn result_digest(&self) -> Sha256Digest {
        self.result_digest
    }

    pub(crate) fn validate_recomputed(
        &self,
        request: &VerificationRequest,
    ) -> Result<(), VerificationError> {
        if self.verification_id != request.verification_id
            || self.run_id != request.run_id
            || self.request_digest != request.request_digest
            || self.expected_candidate_manifest_digest != request.candidate_manifest_digest
            || self.expected_directory_manifest_digest != request.baseline_directory_manifest_digest
            || self.executable_attestation_digest
                != request.specification.executable_attestation_digest()
            || self.executable_attestation_evidence
                != request.specification.executable_attestation_evidence()
            || digest_bytes(self.stdout.text.as_bytes()) != self.stdout.digest
            || self.stdout.text.len() as u64 != self.stdout.byte_length
            || digest_bytes(self.stderr.text.as_bytes()) != self.stderr.digest
            || self.stderr.text.len() as u64 != self.stderr.byte_length
            || self
                .stdout
                .text
                .len()
                .checked_add(self.stderr.text.len())
                .is_none_or(|combined| combined > request.specification.limits.max_output_bytes)
            || (self.outcome == VerificationOutcome::OutputLimitExceeded
                && (!self.stdout.text.is_empty() || !self.stderr.text.is_empty()))
            || (self.outcome == VerificationOutcome::OutputRejected
                && (!self.stdout.text.is_empty() || !self.stderr.text.is_empty()))
            || !duration_within_result_limit(self.duration, request.specification.limits)
            || digest_bytes(&self.canonical_bytes()) != self.result_digest
            || (self.outcome == VerificationOutcome::Passed
                && (self.exit_code != Some(0)
                    || self.observed_candidate_manifest_digest
                        != Some(self.expected_candidate_manifest_digest)
                    || self.observed_directory_manifest_digest
                        != Some(self.expected_directory_manifest_digest)))
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(RESULT_DOMAIN);
        bytes.extend_from_slice(self.verification_id.as_uuid().as_bytes());
        bytes.extend_from_slice(self.run_id.as_uuid().as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(self.expected_candidate_manifest_digest.as_bytes());
        bytes.extend_from_slice(self.expected_directory_manifest_digest.as_bytes());
        bytes.push(self.outcome.tag());
        append_optional_i32(&mut bytes, self.exit_code);
        append_optional_digest(&mut bytes, self.observed_candidate_manifest_digest);
        append_optional_digest(&mut bytes, self.observed_directory_manifest_digest);
        bytes.extend_from_slice(self.executable_attestation_digest.as_bytes());
        append_text(&mut bytes, &self.executable_attestation_evidence);
        bytes.extend_from_slice(&self.stdout.byte_length.to_be_bytes());
        bytes.extend_from_slice(self.stdout.digest.as_bytes());
        bytes.extend_from_slice(&self.stderr.byte_length.to_be_bytes());
        bytes.extend_from_slice(self.stderr.digest.as_bytes());
        append_duration(&mut bytes, self.duration);
        bytes
    }
}

impl fmt::Debug for VerificationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationResult")
            .field("verification_id", &self.verification_id)
            .field("run_id", &self.run_id)
            .field("outcome", &self.outcome)
            .field("result_digest", &self.result_digest)
            .finish_non_exhaustive()
    }
}

pub struct VerifiedProposal {
    verification_id: VerificationId,
    run_id: RunId,
    proposal_artifact_id: ArtifactId,
    candidate_manifest_digest: Sha256Digest,
    directory_manifest_digest: Sha256Digest,
    request_digest: Sha256Digest,
    result_digest: Sha256Digest,
}

impl VerifiedProposal {
    pub(crate) fn from_committed_result(
        request: &VerificationRequest,
        result: &VerificationResult,
    ) -> Result<Self, VerificationError> {
        request.validate_recomputed()?;
        result.validate_recomputed(request)?;
        if result.outcome != VerificationOutcome::Passed {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(Self {
            verification_id: request.verification_id,
            run_id: request.run_id,
            proposal_artifact_id: request.proposal_artifact_id.clone(),
            candidate_manifest_digest: request.candidate_manifest_digest,
            directory_manifest_digest: request.baseline_directory_manifest_digest,
            request_digest: request.request_digest,
            result_digest: result.result_digest,
        })
    }

    #[must_use]
    pub const fn verification_id(&self) -> VerificationId {
        self.verification_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn proposal_artifact_id(&self) -> &ArtifactId {
        &self.proposal_artifact_id
    }

    #[must_use]
    pub const fn candidate_manifest_digest(&self) -> Sha256Digest {
        self.candidate_manifest_digest
    }

    #[must_use]
    pub const fn directory_manifest_digest(&self) -> Sha256Digest {
        self.directory_manifest_digest
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn result_digest(&self) -> Sha256Digest {
        self.result_digest
    }
}

impl fmt::Debug for VerifiedProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProposal")
            .field("verification_id", &self.verification_id)
            .field("run_id", &self.run_id)
            .field("request_digest", &self.request_digest)
            .field("result_digest", &self.result_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct VerifiedCandidateEvidence {
    directories: Vec<String>,
    files: Vec<CandidateFile>,
    manifest_entries: Vec<StageManifestEntry>,
}

struct VerificationExecutionReceipt {
    request_digest: Sha256Digest,
    specification_digest: Sha256Digest,
    executable_attestation_digest: Sha256Digest,
    argument_vector_digest: Sha256Digest,
    candidate_manifest_digest: Sha256Digest,
    directory_manifest_digest: Sha256Digest,
}

impl VerificationExecutionReceipt {
    fn validate(
        &self,
        request: &VerificationRequest,
        specification: &VerificationSpec,
    ) -> Result<(), VerificationError> {
        if self.request_digest != request.request_digest
            || self.specification_digest != specification.specification_digest()
            || self.specification_digest != request.specification.specification_digest()
            || self.executable_attestation_digest
                != request.specification.executable_attestation_digest()
            || self.argument_vector_digest != request.specification.argument_vector_digest()
            || self.candidate_manifest_digest != request.candidate_manifest_digest
            || self.directory_manifest_digest != request.baseline_directory_manifest_digest
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        Ok(())
    }
}

pub async fn run_subscription_verification(
    runtime: &mut RuntimeStore,
    run_id: RunId,
    expected_revision: u64,
    specification: &VerificationSpec,
    verification_parent: &Path,
    cancellation: CancellationToken,
) -> Result<Option<VerificationCompletionRecord>, CarlError> {
    let verifying_revision =
        expected_revision
            .checked_add(1)
            .ok_or_else(|| CarlError::Validation {
                detail: "subscription-run revision overflow".to_owned(),
            })?;
    let Some(request) = runtime.begin_subscription_run_verification(
        run_id,
        expected_revision,
        specification,
        Utc::now(),
    )?
    else {
        return Ok(None);
    };

    let baseline = runtime.get_subscription_run_baseline(run_id)?;
    let proposal = runtime.get_subscription_run_proposal(run_id)?;
    let result = match (baseline, proposal) {
        (Some(baseline), Some(proposal)) => match execute_verification(
            &request,
            specification,
            runtime.artifacts(),
            &baseline,
            &proposal,
            verification_parent,
            cancellation,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => VerificationResult::from_nonpassing_execution(
                &request,
                VerificationOutcome::ProcessFailed,
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                Duration::ZERO,
            )
            .map_err(verification_runtime_error)?,
        },
        _ => VerificationResult::from_nonpassing_execution(
            &request,
            VerificationOutcome::ProcessFailed,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Duration::ZERO,
        )
        .map_err(verification_runtime_error)?,
    };
    runtime.complete_subscription_run_verification(run_id, verifying_revision, &result, Utc::now())
}

fn verification_runtime_error(error: VerificationError) -> CarlError {
    CarlError::Validation {
        detail: format!("verification evidence was rejected ({:?})", error.code()),
    }
}

pub(crate) async fn execute_verification(
    request: &VerificationRequest,
    live_specification: &VerificationSpec,
    artifacts: &ArtifactStore,
    baseline: &SubscriptionRunBaselineRecord,
    proposal: &SubscriptionRunProposalRecord,
    verification_parent: &Path,
    cancellation: CancellationToken,
) -> Result<VerificationResult, VerificationError> {
    request.validate_recomputed()?;
    request.matches_live_specification(live_specification)?;
    validate_persisted_evidence(request.run_id, baseline, proposal)?;
    validate_request_records(request, baseline, proposal)?;

    let verification_parent = std::fs::canonicalize(verification_parent)
        .map_err(|_| VerificationError::new(VerificationErrorCode::Io))?;
    if artifacts
        .overlaps_canonical_path(&verification_parent)
        .map_err(|_| VerificationError::new(VerificationErrorCode::Io))?
    {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }

    let evidence = load_verified_candidate_evidence(artifacts, baseline, proposal)?;
    let candidate = VerificationCandidate::reconstruct(
        &verification_parent,
        &evidence.directories,
        &evidence.files,
    )
    .map_err(|_| VerificationError::new(VerificationErrorCode::CandidateInvalid))?;
    let scratch = match VerificationCandidate::reconstruct(&verification_parent, &[], &[]) {
        Ok(scratch) => scratch,
        Err(_) => {
            let _ = candidate.cleanup();
            return Err(VerificationError::new(
                VerificationErrorCode::CandidateInvalid,
            ));
        }
    };

    let proposal_limits = ProposalLimits::new(1024 * 1024)
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidLimits))?;
    let pre_execution = match candidate.inspect(
        &evidence.manifest_entries,
        &evidence.directories,
        proposal_limits,
        SecretFilter,
    ) {
        Ok(seal)
            if seal.matches_expected_manifest(
                request.candidate_manifest_digest,
                request.baseline_directory_manifest_digest,
            ) =>
        {
            seal
        }
        _ => {
            let _ = candidate.cleanup();
            let _ = scratch.cleanup();
            return Err(VerificationError::new(
                VerificationErrorCode::CandidateInvalid,
            ));
        }
    };

    let workspace = candidate
        .execution_workspace()
        .map_err(|_| VerificationError::new(VerificationErrorCode::CandidateInvalid))?;
    let environment = clean_environment(live_specification, scratch.path())?;
    let arguments = live_specification
        .arguments()
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let limits = live_specification.limits().as_process_limits()?;
    let pre_attestation_valid = live_specification
        .executable()
        .revalidate_verification_attestation(live_specification.executable_attestation())
        .is_ok();
    let execution = if pre_attestation_valid {
        run_bounded_process(
            live_specification.executable(),
            &arguments,
            &environment,
            &workspace,
            limits,
            cancellation,
        )
        .await
        .ok()
    } else {
        None
    };
    let post_attestation_valid = live_specification
        .executable()
        .revalidate_verification_attestation(live_specification.executable_attestation())
        .is_ok();

    let (mut outcome, exit_code, stdout, stderr, duration) = match execution {
        Some(result) => {
            let stdout = result.stdout().to_vec();
            let stderr = result.stderr().to_vec();
            let duration = result.duration();
            let (outcome, exit_code) = match result.outcome() {
                BoundedProcessOutcome::Exited(status) if status.success() => {
                    (VerificationOutcome::Passed, Some(0))
                }
                BoundedProcessOutcome::Exited(status) => match status.code() {
                    Some(code) if code != 0 => (VerificationOutcome::NonZeroExit, Some(code)),
                    _ => (VerificationOutcome::ProcessFailed, None),
                },
                BoundedProcessOutcome::TimedOut => (VerificationOutcome::TimedOut, None),
                BoundedProcessOutcome::Cancelled => (VerificationOutcome::Cancelled, None),
                BoundedProcessOutcome::OutputLimitExceeded => {
                    (VerificationOutcome::OutputLimitExceeded, None)
                }
            };
            (outcome, exit_code, stdout, stderr, duration)
        }
        None => (
            VerificationOutcome::ProcessFailed,
            None,
            Vec::new(),
            Vec::new(),
            Duration::ZERO,
        ),
    };
    if !pre_attestation_valid || !post_attestation_valid {
        outcome = VerificationOutcome::ProcessFailed;
    }

    let post_execution_first = candidate.inspect(
        &evidence.manifest_entries,
        &evidence.directories,
        proposal_limits,
        SecretFilter,
    );
    let post_execution_second = candidate.inspect(
        &evidence.manifest_entries,
        &evidence.directories,
        proposal_limits,
        SecretFilter,
    );
    let (observed_manifest, observed_directories, candidate_unchanged) =
        match (post_execution_first, post_execution_second) {
            (Ok(first), Ok(second)) => {
                let expected = first.matches_expected_manifest(
                    request.candidate_manifest_digest,
                    request.baseline_directory_manifest_digest,
                ) && second.matches_expected_manifest(
                    request.candidate_manifest_digest,
                    request.baseline_directory_manifest_digest,
                );
                (
                    Some(second.manifest_digest()),
                    Some(second.directory_manifest_digest()),
                    expected
                        && pre_execution.same_persistent_snapshot(&first)
                        && first.same_persistent_snapshot(&second),
                )
            }
            _ => (None, None, false),
        };
    let artifacts_unchanged = load_verified_candidate_evidence(artifacts, baseline, proposal)
        .is_ok_and(|after| after == evidence);
    if !candidate_unchanged || !artifacts_unchanged {
        outcome = VerificationOutcome::CandidateMutated;
    }

    drop(workspace);
    let candidate_cleanup_succeeded = candidate.cleanup().is_ok();
    let scratch_cleanup_succeeded = scratch.cleanup().is_ok();
    let cleanup_succeeded = candidate_cleanup_succeeded && scratch_cleanup_succeeded;
    if !cleanup_succeeded {
        outcome = VerificationOutcome::ProcessFailed;
    }

    if outcome == VerificationOutcome::Passed {
        let receipt = VerificationExecutionReceipt {
            request_digest: request.request_digest,
            specification_digest: live_specification.specification_digest(),
            executable_attestation_digest: request.specification.executable_attestation_digest(),
            argument_vector_digest: live_specification.argument_vector_digest(),
            candidate_manifest_digest: observed_manifest
                .ok_or_else(|| VerificationError::new(VerificationErrorCode::CandidateInvalid))?,
            directory_manifest_digest: observed_directories
                .ok_or_else(|| VerificationError::new(VerificationErrorCode::CandidateInvalid))?,
        };
        receipt.validate(request, live_specification)?;
        return VerificationResult::from_verified_execution(
            request,
            live_specification,
            &receipt,
            stdout,
            stderr,
            duration,
        );
    }

    VerificationResult::from_nonpassing_execution(
        request,
        outcome,
        exit_code,
        observed_manifest,
        observed_directories,
        stdout,
        stderr,
        duration,
    )
}

fn validate_request_records(
    request: &VerificationRequest,
    baseline: &SubscriptionRunBaselineRecord,
    proposal: &SubscriptionRunProposalRecord,
) -> Result<(), VerificationError> {
    if request.run_id != baseline.run_id
        || request.run_id != proposal.run_id
        || request.baseline_manifest_artifact_id != baseline.manifest_artifact_id
        || request.baseline_manifest_digest != baseline.manifest_digest
        || request.source_preconditions_artifact_id != baseline.source_preconditions_artifact_id
        || request.source_preconditions_digest != baseline.source_preconditions_digest
        || request.baseline_directory_manifest_digest != baseline.directory_manifest_digest
        || request.proposal_artifact_id != proposal.proposal_artifact_id
        || request.payload_artifact_id != proposal.payload_artifact_id
        || request.payload_digest != proposal.payload_hash
        || request.candidate_manifest_digest != proposal.candidate_manifest_digest
    {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }
    Ok(())
}

fn load_verified_candidate_evidence(
    artifacts: &ArtifactStore,
    baseline: &SubscriptionRunBaselineRecord,
    proposal: &SubscriptionRunProposalRecord,
) -> Result<VerifiedCandidateEvidence, VerificationError> {
    validate_persisted_evidence(baseline.run_id, baseline, proposal)?;
    let entry_count = u64::try_from(baseline.entries.len())
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    if entry_count != baseline.entry_count {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }

    let mut manifest_entries = Vec::with_capacity(baseline.entries.len());
    let mut files = Vec::with_capacity(baseline.entries.len());
    let mut total_bytes = 0_u64;
    let mut previous_path: Option<&str> = None;
    for (index, entry) in baseline.entries.iter().enumerate() {
        validate_relative_path(&entry.path)?;
        if entry.ordinal
            != u64::try_from(index)
                .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?
            || previous_path.is_some_and(|previous| previous >= entry.path.as_str())
            || entry.content_artifact_id.as_str() != entry.content_digest.to_string()
            || !matches!(
                (entry.identity_platform.as_str(), entry.owner_mode),
                ("unix", Some(0..=0o7777)) | ("windows", None)
            )
            || entry.identity_a.is_empty()
            || entry.identity_b.is_empty()
            || entry.owner_id.is_empty()
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        let stored = artifacts
            .read_verified(&entry.content_artifact_id)
            .map_err(|_| VerificationError::new(VerificationErrorCode::ArtifactCorrupt))?;
        if stored.bytes().len() as u64 != entry.byte_length
            || digest_bytes(stored.bytes()) != entry.content_digest
        {
            return Err(VerificationError::new(
                VerificationErrorCode::ArtifactCorrupt,
            ));
        }
        total_bytes = total_bytes
            .checked_add(entry.byte_length)
            .ok_or_else(|| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
        manifest_entries.push(StageManifestEntry::new(
            entry.path.clone(),
            entry.byte_length,
            entry.content_digest,
        ));
        files.push(CandidateFile {
            path: entry.path.clone(),
            bytes: stored.bytes().to_vec(),
        });
        previous_path = Some(&entry.path);
    }
    if total_bytes != baseline.total_bytes {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }

    let canonical_manifest = canonical_manifest_bytes(&manifest_entries)
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    let stored_manifest = artifacts
        .read_verified(&baseline.manifest_artifact_id)
        .map_err(|_| VerificationError::new(VerificationErrorCode::ArtifactCorrupt))?;
    if digest_bytes(&canonical_manifest) != baseline.manifest_digest
        || stored_manifest.bytes() != canonical_manifest
    {
        return Err(VerificationError::new(
            VerificationErrorCode::ArtifactCorrupt,
        ));
    }

    let canonical_preconditions = canonical_source_preconditions(
        baseline.manifest_digest,
        baseline.entries.iter().map(|entry| SourcePreconditionRef {
            path: &entry.path,
            bytes: entry.byte_length,
            content_digest: entry.content_digest,
            platform: &entry.identity_platform,
            identity_a: &entry.identity_a,
            identity_b: &entry.identity_b,
            owner_id: &entry.owner_id,
            owner_mode: entry.owner_mode,
        }),
    )
    .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    let stored_preconditions = artifacts
        .read_verified(&baseline.source_preconditions_artifact_id)
        .map_err(|_| VerificationError::new(VerificationErrorCode::ArtifactCorrupt))?;
    if digest_bytes(&canonical_preconditions) != baseline.source_preconditions_digest
        || stored_preconditions.bytes() != canonical_preconditions
    {
        return Err(VerificationError::new(
            VerificationErrorCode::ArtifactCorrupt,
        ));
    }

    let payload = artifacts
        .read_verified(&proposal.payload_artifact_id)
        .map_err(|_| VerificationError::new(VerificationErrorCode::ArtifactCorrupt))?;
    if payload.bytes().len() as u64 != proposal.payload_bytes
        || digest_bytes(payload.bytes()) != proposal.payload_hash
    {
        return Err(VerificationError::new(
            VerificationErrorCode::ArtifactCorrupt,
        ));
    }
    let canonical_proposal = canonical_proposal_envelope(
        baseline.manifest_digest,
        &proposal.path,
        proposal.expected_live_hash,
        proposal.before_hash,
        proposal.after_hash,
        proposal.payload_hash,
        payload.bytes(),
    )
    .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    let stored_proposal = artifacts
        .read_verified(&proposal.proposal_artifact_id)
        .map_err(|_| VerificationError::new(VerificationErrorCode::ArtifactCorrupt))?;
    if stored_proposal.bytes() != canonical_proposal {
        return Err(VerificationError::new(
            VerificationErrorCode::ArtifactCorrupt,
        ));
    }

    let index = manifest_entries
        .binary_search_by(|entry| entry.path().cmp(&proposal.path))
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    manifest_entries[index] = StageManifestEntry::new(
        proposal.path.clone(),
        proposal.payload_bytes,
        proposal.payload_hash,
    );
    files[index] = CandidateFile {
        path: proposal.path.clone(),
        bytes: payload.bytes().to_vec(),
    };
    let candidate_manifest = canonical_manifest_bytes(&manifest_entries)
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    if digest_bytes(&candidate_manifest) != proposal.candidate_manifest_digest {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }
    Ok(VerifiedCandidateEvidence {
        directories: baseline.directories.clone(),
        files,
        manifest_entries,
    })
}

fn clean_environment(
    specification: &VerificationSpec,
    scratch: &Path,
) -> Result<ClosedEnvironment, VerificationError> {
    let executable_parent = specification
        .executable()
        .canonical_path()
        .parent()
        .ok_or_else(|| VerificationError::new(VerificationErrorCode::UnsafeExecutable))?;
    let path = std::env::join_paths([PathBuf::from(executable_parent)])
        .map_err(|_| VerificationError::new(VerificationErrorCode::UnsafeExecutable))?;
    let scratch = scratch.as_os_str().to_os_string();
    let mut entries = vec![
        (OsString::from("HOME"), scratch.clone()),
        (OsString::from("PATH"), path),
        (OsString::from("TEMP"), scratch.clone()),
        (OsString::from("TMP"), scratch.clone()),
        (OsString::from("CARL_VERIFICATION"), OsString::from("1")),
    ];
    #[cfg(unix)]
    entries.push((OsString::from("TMPDIR"), scratch.clone()));
    #[cfg(windows)]
    entries.push((OsString::from("USERPROFILE"), scratch));
    ClosedEnvironment::new(entries)
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidLimits))
}

fn validate_persisted_evidence(
    run_id: RunId,
    baseline: &SubscriptionRunBaselineRecord,
    proposal: &SubscriptionRunProposalRecord,
) -> Result<(), VerificationError> {
    let canonical_directories = canonical_directory_manifest(&baseline.directories)?;
    let directory_count = u64::try_from(baseline.directories.len())
        .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
    let matching_entry = baseline
        .entries
        .iter()
        .find(|entry| entry.path == proposal.path);
    if baseline.run_id != run_id
        || proposal.run_id != run_id
        || baseline.manifest_artifact_id.as_str() != baseline.manifest_digest.to_string()
        || baseline.source_preconditions_artifact_id.as_str()
            != baseline.source_preconditions_digest.to_string()
        || baseline.directory_count != directory_count
        || digest_bytes(&canonical_directories) != baseline.directory_manifest_digest
        || proposal.baseline_manifest_artifact_id != baseline.manifest_artifact_id
        || proposal.payload_artifact_id.as_str() != proposal.payload_hash.to_string()
        || proposal.after_hash != proposal.payload_hash
        || proposal.expected_live_hash != proposal.before_hash
        || matching_entry.is_none_or(|entry| entry.content_digest != proposal.before_hash)
    {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), VerificationError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidArguments,
        ));
    }
    let mut total_bytes = 0_usize;
    for argument in arguments {
        if argument.contains('\0')
            || argument.len() > MAX_ARGUMENT_BYTES
            || SecretFilter.inspect(argument.as_bytes()).is_err()
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidArguments,
            ));
        }
        total_bytes = total_bytes
            .checked_add(argument.len())
            .ok_or_else(|| VerificationError::new(VerificationErrorCode::InvalidArguments))?;
        if total_bytes > MAX_ARGUMENT_TOTAL_BYTES {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidArguments,
            ));
        }
    }
    Ok(())
}

fn canonical_specification(
    executable: &VerificationExecutableEvidence,
    arguments: &[String],
    environment_profile: VerificationEnvironmentProfile,
    limits: VerificationLimits,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SPECIFICATION_DOMAIN);
    let attestation = executable.canonical_bytes();
    bytes.extend_from_slice(digest_bytes(&attestation).as_bytes());
    append_bytes(&mut bytes, &attestation);
    let arguments = canonical_arguments(arguments);
    bytes.extend_from_slice(digest_bytes(&arguments).as_bytes());
    append_bytes(&mut bytes, &arguments);
    bytes.push(environment_profile.tag());
    append_duration(&mut bytes, limits.execution_timeout);
    bytes.extend_from_slice(
        &u64::try_from(limits.max_output_bytes)
            .expect("validated output length fits u64")
            .to_be_bytes(),
    );
    append_duration(&mut bytes, limits.graceful_shutdown_timeout);
    append_duration(&mut bytes, limits.forced_shutdown_timeout);
    append_duration(&mut bytes, limits.poll_interval);
    bytes
}

fn canonical_arguments(arguments: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ARGUMENTS_DOMAIN);
    bytes.extend_from_slice(
        &u32::try_from(arguments.len())
            .expect("validated argument count fits u32")
            .to_be_bytes(),
    );
    for argument in arguments {
        append_text(&mut bytes, argument);
    }
    bytes
}

fn canonical_directory_manifest(directories: &[String]) -> Result<Vec<u8>, VerificationError> {
    if directories.len() > MAX_DIRECTORY_COUNT {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }
    let mut bytes = Vec::new();
    let mut aggregate_path_bytes = 0_usize;
    let mut previous: Option<&str> = None;
    bytes.extend_from_slice(DIRECTORY_MANIFEST_DOMAIN);
    bytes.extend_from_slice(
        &u32::try_from(directories.len())
            .map_err(|_| VerificationError::new(VerificationErrorCode::InvalidEvidence))?
            .to_be_bytes(),
    );
    for directory in directories {
        validate_relative_path(directory)?;
        if previous.is_some_and(|previous| previous >= directory.as_str()) {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        if let Some((parent, _)) = directory.rsplit_once('/')
            && directories
                .binary_search_by(|candidate| candidate.as_str().cmp(parent))
                .is_err()
        {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        aggregate_path_bytes = aggregate_path_bytes
            .checked_add(directory.len())
            .ok_or_else(|| VerificationError::new(VerificationErrorCode::InvalidEvidence))?;
        if aggregate_path_bytes > MAX_AGGREGATE_PATH_BYTES {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidEvidence,
            ));
        }
        append_text(&mut bytes, directory);
        previous = Some(directory);
    }
    Ok(bytes)
}

fn validate_relative_path(path: &str) -> Result<(), VerificationError> {
    if path.is_empty()
        || path.len() > MAX_RELATIVE_PATH_BYTES
        || path.contains('\\')
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidEvidence,
        ));
    }
    Ok(())
}

fn append_duration(bytes: &mut Vec<u8>, duration: Duration) {
    bytes.extend_from_slice(
        &u64::try_from(duration.as_nanos())
            .expect("validated duration fits u64 nanoseconds")
            .to_be_bytes(),
    );
}

fn duration_within_result_limit(duration: Duration, limits: VerificationLimits) -> bool {
    limits
        .execution_timeout
        .checked_add(limits.graceful_shutdown_timeout)
        .and_then(|maximum| maximum.checked_add(limits.forced_shutdown_timeout))
        .and_then(|maximum| maximum.checked_add(limits.forced_shutdown_timeout))
        .and_then(|maximum| maximum.checked_add(limits.poll_interval))
        .is_some_and(|maximum| duration <= maximum)
}

fn append_optional_i32(bytes: &mut Vec<u8>, value: Option<i32>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn append_optional_digest(bytes: &mut Vec<u8>, value: Option<Sha256Digest>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(value.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn append_text(bytes: &mut Vec<u8>, value: &str) {
    append_bytes(bytes, value.as_bytes());
}

fn append_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .expect("validated canonical field length fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value);
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use chrono::Utc;
    use semver::VersionReq;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        VerificationEnvironmentProfile, VerificationLimits, VerificationOutcome,
        VerificationRequest, VerificationResult, VerificationSpec, VerifiedProposal,
    };
    use crate::artifacts::ArtifactId;
    use crate::artifacts::ArtifactStore;
    use crate::policy::Sha256Digest;
    use crate::runtime::subscription::{RunId, VerificationId};
    use crate::sidecar::{
        ExecutableTrustDecision, SidecarCommand, TrustedExecutable, VersionOutputFormat,
    };
    use crate::staging::{
        SourcePreconditionRef, StageManifestEntry, canonical_manifest_bytes,
        canonical_proposal_envelope, canonical_source_preconditions,
    };
    use crate::storage::{
        SubscriptionRunBaselineEntryRecord, SubscriptionRunBaselineRecord,
        SubscriptionRunProposalRecord,
    };
    use tokio_util::sync::CancellationToken;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn verification_limits_reject_unbounded_values() -> TestResult {
        assert!(
            VerificationLimits::new(
                Duration::ZERO,
                1,
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .is_err()
        );
        assert!(
            VerificationLimits::new(
                Duration::from_secs(1),
                1024 * 1024 + 1,
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn verification_spec_rejects_nul_and_secret_arguments() -> TestResult {
        let limits = verification_limits()?;
        assert!(
            VerificationSpec::new(
                trusted_fixture()?,
                vec!["bad\0argument".to_owned()],
                VerificationEnvironmentProfile::CleanV1,
                limits,
            )
            .is_err()
        );
        assert!(
            VerificationSpec::new(
                trusted_fixture()?,
                vec!["token=\"sk-1234567890abcdefghijklmnop\"".to_owned()],
                VerificationEnvironmentProfile::CleanV1,
                limits,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn verification_spec_digest_binds_argument_order_and_limits() -> TestResult {
        let first = VerificationSpec::new(
            trusted_fixture()?,
            vec!["first".to_owned(), "second".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            verification_limits()?,
        )?;
        let same = VerificationSpec::new(
            trusted_fixture()?,
            vec!["first".to_owned(), "second".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            verification_limits()?,
        )?;
        let reordered = VerificationSpec::new(
            trusted_fixture()?,
            vec!["second".to_owned(), "first".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            verification_limits()?,
        )?;
        let shorter_timeout = VerificationSpec::new(
            trusted_fixture()?,
            vec!["first".to_owned(), "second".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            VerificationLimits::new(
                Duration::from_secs(4),
                64 * 1024,
                Duration::from_millis(250),
                Duration::from_secs(2),
                Duration::from_millis(5),
            )?,
        )?;

        assert_eq!(first.specification_digest(), same.specification_digest());
        assert_ne!(
            first.specification_digest(),
            reordered.specification_digest()
        );
        assert_ne!(
            first.specification_digest(),
            shorter_timeout.specification_digest()
        );
        assert!(!format!("{first:?}").contains("second"));
        Ok(())
    }

    #[test]
    fn verification_request_digest_binds_durable_directory_topology() -> TestResult {
        let run_id = RunId::from_uuid(Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?);
        let verification_id =
            VerificationId::from_uuid(Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?);
        let specification = VerificationSpec::new(
            trusted_fixture()?,
            vec!["--check".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            verification_limits()?,
        )?;
        let proposal = proposal_record(run_id)?;
        let baseline = baseline_record(run_id, vec!["src".to_owned()])?;
        let request = VerificationRequest::from_persisted(
            verification_id,
            run_id,
            &baseline,
            &proposal,
            &specification,
        )?;

        let with_empty_directory =
            baseline_record(run_id, vec!["src".to_owned(), "src/empty".to_owned()])?;
        let changed = VerificationRequest::from_persisted(
            verification_id,
            run_id,
            &with_empty_directory,
            &proposal,
            &specification,
        )?;

        assert_eq!(request.run_id(), run_id);
        assert_eq!(request.verification_id(), verification_id);
        assert_eq!(
            request.candidate_manifest_digest(),
            proposal.candidate_manifest_digest
        );
        assert_ne!(request.request_digest(), changed.request_digest());
        assert!(request.validate_recomputed().is_ok());
        Ok(())
    }

    #[test]
    fn passed_result_binds_post_run_topology_and_clean_diagnostics() -> TestResult {
        let (request, _baseline, proposal) = request_fixture()?;
        let result = VerificationResult::from_observation(
            &request,
            VerificationOutcome::Passed,
            Some(0),
            Some(request.candidate_manifest_digest()),
            Some(request.baseline_directory_manifest_digest()),
            b"tests passed\n".to_vec(),
            Vec::new(),
        )?;
        let changed_output = VerificationResult::from_observation(
            &request,
            VerificationOutcome::Passed,
            Some(0),
            Some(request.candidate_manifest_digest()),
            Some(request.baseline_directory_manifest_digest()),
            b"different clean output\n".to_vec(),
            Vec::new(),
        )?;

        assert_eq!(result.outcome(), VerificationOutcome::Passed);
        assert_eq!(result.stdout().text(), "tests passed\n");
        assert_ne!(result.result_digest(), changed_output.result_digest());
        assert!(
            VerificationResult::from_observation(
                &request,
                VerificationOutcome::Passed,
                Some(0),
                Some(request.candidate_manifest_digest()),
                Some(test_digest(b"wrong-directory-topology")),
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
        let verified = VerifiedProposal::from_committed_result(&request, &result)?;
        assert_eq!(verified.run_id(), request.run_id());
        assert_eq!(
            verified.proposal_artifact_id(),
            &proposal.proposal_artifact_id
        );
        assert_eq!(verified.result_digest(), result.result_digest());
        Ok(())
    }

    #[test]
    fn rejected_output_discards_raw_secret_and_cannot_verify() -> TestResult {
        let (request, _baseline, _proposal) = request_fixture()?;
        let result = VerificationResult::from_observation(
            &request,
            VerificationOutcome::Passed,
            Some(0),
            Some(request.candidate_manifest_digest()),
            Some(request.baseline_directory_manifest_digest()),
            b"token=sk-1234567890abcdefghijklmnop".to_vec(),
            Vec::new(),
        )?;

        assert_eq!(result.outcome(), VerificationOutcome::OutputRejected);
        assert!(!result.stdout().text().contains("sk-"));
        assert!(VerifiedProposal::from_committed_result(&request, &result).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verifier_reconstructs_artifacts_runs_and_removes_workspaces() -> TestResult {
        let root =
            std::env::current_dir()?.join(format!(".carl-verification-runner-{}", Uuid::new_v4()));
        let _root_cleanup = VerificationTestRoot(root.clone());
        let artifacts_path = root.join("artifacts");
        let verification_parent = root.join("verification");
        for path in [&root, &artifacts_path, &verification_parent] {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let specification = VerificationSpec::new(
            executable,
            vec![
                "-c".to_owned(),
                "printf 'verification passed\\n'".to_owned(),
            ],
            VerificationEnvironmentProfile::CleanV1,
            verification_limits()?,
        )?;

        let store = ArtifactStore::open(&artifacts_path)?;
        let run_id = RunId::from_uuid(Uuid::new_v4());
        let verification_id = VerificationId::from_uuid(Uuid::new_v4());
        let path = "src/file.txt";
        let before = b"before\n";
        let after = b"after\n";
        let before_digest = test_digest(before);
        let after_digest = test_digest(after);
        let baseline_entry =
            StageManifestEntry::new(path.to_owned(), before.len() as u64, before_digest);
        let baseline_manifest = canonical_manifest_bytes(&[baseline_entry])?;
        let baseline_manifest_digest = test_digest(&baseline_manifest);
        let baseline_manifest_artifact = store.put(&baseline_manifest)?;
        let content_artifact = store.put(before)?;
        let source_preconditions = canonical_source_preconditions(
            baseline_manifest_digest,
            std::iter::once(SourcePreconditionRef {
                path,
                bytes: before.len() as u64,
                content_digest: before_digest,
                platform: "unix",
                identity_a: "1",
                identity_b: "2",
                owner_id: "3",
                owner_mode: Some(0o600),
            }),
        )?;
        let source_preconditions_artifact = store.put(&source_preconditions)?;
        let payload_artifact = store.put(after)?;
        let candidate_manifest = canonical_manifest_bytes(&[StageManifestEntry::new(
            path.to_owned(),
            after.len() as u64,
            after_digest,
        )])?;
        let candidate_manifest_digest = test_digest(&candidate_manifest);
        let proposal_envelope = canonical_proposal_envelope(
            baseline_manifest_digest,
            path,
            before_digest,
            before_digest,
            after_digest,
            after_digest,
            after,
        )?;
        let proposal_artifact = store.put(&proposal_envelope)?;
        let directories = vec!["src".to_owned(), "src/empty".to_owned()];
        let baseline = SubscriptionRunBaselineRecord {
            run_id,
            manifest_artifact_id: baseline_manifest_artifact.id().clone(),
            manifest_digest: baseline_manifest_digest,
            source_preconditions_artifact_id: source_preconditions_artifact.id().clone(),
            source_preconditions_digest: test_digest(&source_preconditions),
            entry_count: 1,
            total_bytes: before.len() as u64,
            directory_count: directories.len() as u64,
            directory_manifest_digest: test_directory_digest(&directories),
            entries: vec![SubscriptionRunBaselineEntryRecord {
                ordinal: 0,
                path: path.to_owned(),
                byte_length: before.len() as u64,
                content_digest: before_digest,
                content_artifact_id: content_artifact.id().clone(),
                identity_platform: "unix".to_owned(),
                identity_a: "1".to_owned(),
                identity_b: "2".to_owned(),
                owner_id: "3".to_owned(),
                owner_mode: Some(0o600),
            }],
            directories,
            created_at: Utc::now(),
        };
        let proposal = SubscriptionRunProposalRecord {
            run_id,
            proposal_artifact_id: proposal_artifact.id().clone(),
            payload_artifact_id: payload_artifact.id().clone(),
            baseline_manifest_artifact_id: baseline_manifest_artifact.id().clone(),
            candidate_manifest_digest,
            path: path.to_owned(),
            expected_live_hash: before_digest,
            before_hash: before_digest,
            after_hash: after_digest,
            payload_hash: after_digest,
            payload_bytes: after.len() as u64,
            created_at: Utc::now(),
        };
        let request = VerificationRequest::from_persisted(
            verification_id,
            run_id,
            &baseline,
            &proposal,
            &specification,
        )?;

        let result = super::execute_verification(
            &request,
            &specification,
            &store,
            &baseline,
            &proposal,
            &verification_parent,
            CancellationToken::new(),
        )
        .await?;

        assert_eq!(result.outcome(), VerificationOutcome::Passed);
        assert_eq!(result.stdout().text(), "verification passed\n");
        assert!(
            fs::read_dir(&verification_parent)?.next().is_none(),
            "candidate and scratch directories must be removed before Passed"
        );
        drop(store);
        Ok(())
    }

    #[cfg(unix)]
    struct VerificationTestRoot(PathBuf);

    #[cfg(unix)]
    impl Drop for VerificationTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn trusted_fixture() -> TestResult<TrustedExecutable> {
        let command = SidecarCommand {
            executable: std::env::current_exe()?,
            arguments: Vec::new(),
            version_arguments: vec![OsString::from("--version")],
            version_output: VersionOutputFormat::SingleSemverToken,
            isolated_home: PathBuf::from("verification-unit"),
            supported_versions: VersionReq::parse(">=0.0.0")?,
        };
        let resolved = command.resolve_executable()?;
        let decision = if resolved.metadata_risk().is_some() {
            ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk
        } else {
            ExecutableTrustDecision::TrustCanonicalPath
        };
        Ok(resolved.trust(decision)?)
    }

    fn verification_limits() -> TestResult<VerificationLimits> {
        Ok(VerificationLimits::new(
            Duration::from_secs(5),
            64 * 1024,
            Duration::from_millis(250),
            Duration::from_secs(2),
            Duration::from_millis(5),
        )?)
    }

    fn request_fixture() -> TestResult<(
        VerificationRequest,
        SubscriptionRunBaselineRecord,
        SubscriptionRunProposalRecord,
    )> {
        let run_id = RunId::from_uuid(Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?);
        let verification_id =
            VerificationId::from_uuid(Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?);
        let baseline = baseline_record(run_id, vec!["src".to_owned()])?;
        let proposal = proposal_record(run_id)?;
        let specification = VerificationSpec::new(
            trusted_fixture()?,
            vec!["--check".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            verification_limits()?,
        )?;
        let request = VerificationRequest::from_persisted(
            verification_id,
            run_id,
            &baseline,
            &proposal,
            &specification,
        )?;
        Ok((request, baseline, proposal))
    }

    fn baseline_record(
        run_id: RunId,
        directories: Vec<String>,
    ) -> TestResult<SubscriptionRunBaselineRecord> {
        let path = "src/file.txt";
        let before = b"before";
        let content_digest = test_digest(before);
        let manifest = canonical_file_manifest(path, before.len() as u64, content_digest);
        let manifest_digest = test_digest(&manifest);
        let source_preconditions_digest = test_digest(b"source-preconditions-fixture");
        Ok(SubscriptionRunBaselineRecord {
            run_id,
            manifest_artifact_id: artifact_id(manifest_digest)?,
            manifest_digest,
            source_preconditions_artifact_id: artifact_id(source_preconditions_digest)?,
            source_preconditions_digest,
            entry_count: 1,
            total_bytes: before.len() as u64,
            directory_count: directories.len() as u64,
            directory_manifest_digest: test_directory_digest(&directories),
            entries: vec![SubscriptionRunBaselineEntryRecord {
                ordinal: 0,
                path: path.to_owned(),
                byte_length: before.len() as u64,
                content_digest,
                content_artifact_id: artifact_id(content_digest)?,
                identity_platform: "unix".to_owned(),
                identity_a: "1".to_owned(),
                identity_b: "2".to_owned(),
                owner_id: "3".to_owned(),
                owner_mode: Some(0o600),
            }],
            directories,
            created_at: Utc::now(),
        })
    }

    fn proposal_record(run_id: RunId) -> TestResult<SubscriptionRunProposalRecord> {
        let path = "src/file.txt";
        let before_hash = test_digest(b"before");
        let payload = b"after";
        let payload_hash = test_digest(payload);
        let candidate_manifest_digest = test_digest(&canonical_file_manifest(
            path,
            payload.len() as u64,
            payload_hash,
        ));
        let baseline_manifest_digest = test_digest(&canonical_file_manifest(path, 6, before_hash));
        Ok(SubscriptionRunProposalRecord {
            run_id,
            proposal_artifact_id: artifact_id(test_digest(b"proposal-envelope"))?,
            payload_artifact_id: artifact_id(payload_hash)?,
            baseline_manifest_artifact_id: artifact_id(baseline_manifest_digest)?,
            candidate_manifest_digest,
            path: path.to_owned(),
            expected_live_hash: before_hash,
            before_hash,
            after_hash: payload_hash,
            payload_hash,
            payload_bytes: payload.len() as u64,
            created_at: Utc::now(),
        })
    }

    fn canonical_file_manifest(path: &str, len: u64, digest: Sha256Digest) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(digest.as_bytes());
        bytes
    }

    fn test_directory_digest(directories: &[String]) -> Sha256Digest {
        let mut bytes = b"carl.baseline-directories.v1\0".to_vec();
        bytes.extend_from_slice(&(directories.len() as u32).to_be_bytes());
        for directory in directories {
            bytes.extend_from_slice(&(directory.len() as u32).to_be_bytes());
            bytes.extend_from_slice(directory.as_bytes());
        }
        test_digest(&bytes)
    }

    fn test_digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }

    fn artifact_id(digest: Sha256Digest) -> TestResult<ArtifactId> {
        Ok(ArtifactId::parse(digest.to_string())?)
    }
}
