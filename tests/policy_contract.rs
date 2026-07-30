use std::collections::BTreeSet;
use std::error::Error;

use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::{SessionId, TurnId};
use carl::policy::{
    ActorId, ActorIdentity, CapabilityRequest, DefaultPolicy, EnvironmentGrant, Frontend,
    PolicyDisposition, PolicyReasonCode, ProviderNetwork, Sha256Digest,
};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;

const PROMPT_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const STAGE_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VERIFICATION_SPEC_DIGEST: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const EXPECTED_REQUEST_DIGEST: &str =
    "3e5f468b675e43c10d5596657c78f41a0299409d7e39293484e1b31ac21567b8";

#[test]
fn delegate_approval_digest_binds_the_exact_verification_specification() -> TestResult {
    let request = CapabilityRequest::external_agent(
        "delegate.codex",
        ActorIdentity::new(ActorId::parse("local-owner")?, Frontend::Cli),
        session_id("11111111-1111-4111-8111-111111111111")?,
        turn_id("22222222-2222-4222-8222-222222222222")?,
        Sha256Digest::parse(PROMPT_DIGEST)?,
        Sha256Digest::parse(STAGE_DIGEST)?,
        Sha256Digest::parse(VERIFICATION_SPEC_DIGEST)?,
        Some(ModelId::parse("gpt-5.6")?),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?;
    let changed = CapabilityRequest::external_agent(
        "delegate.codex",
        ActorIdentity::new(ActorId::parse("local-owner")?, Frontend::Cli),
        session_id("11111111-1111-4111-8111-111111111111")?,
        turn_id("22222222-2222-4222-8222-222222222222")?,
        Sha256Digest::parse(PROMPT_DIGEST)?,
        Sha256Digest::parse(STAGE_DIGEST)?,
        Sha256Digest::parse("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")?,
        Some(ModelId::parse("gpt-5.6")?),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?;

    let encoded = serde_json::to_value(&request)?;
    assert_eq!(
        encoded["verification_specification_digest"],
        VERIFICATION_SPEC_DIGEST
    );
    assert_ne!(request.digest(), changed.digest());
    Ok(())
}

#[test]
fn normalized_request_digest_covers_every_security_relevant_field() -> TestResult {
    let request = safe_request(Frontend::Cli)?;
    assert_eq!(
        request.digest().to_string(),
        EXPECTED_REQUEST_DIGEST,
        "canonical request: {}",
        serde_json::to_string(&request)?
    );
    assert_eq!(safe_request(Frontend::Cli)?.digest(), request.digest());

    let mut changed = Vec::new();
    changed.push(request_with(
        Frontend::Tui,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "different-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "33333333-3333-4333-8333-333333333333",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "44444444-4444-4444-8444-444444444444",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        &format!("c{}", &PROMPT_DIGEST[1..]),
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        &format!("c{}", &STAGE_DIGEST[1..]),
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6-terra"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::Low),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::XaiGrok,
        BTreeSet::new(),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::from([EnvironmentGrant::Credential]),
        false,
    )?);
    changed.push(request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        true,
    )?);

    assert!(
        changed
            .iter()
            .all(|changed| changed.digest() != request.digest())
    );
    Ok(())
}

#[test]
fn serialized_requests_contain_no_prompt_or_ambient_path() -> TestResult {
    let encoded = serde_json::to_value(safe_request(Frontend::Cli)?)?;
    let object = encoded
        .as_object()
        .ok_or("capability request must serialize as an object")?;

    assert_eq!(object["prompt_digest"], PROMPT_DIGEST);
    assert_eq!(object["stage_manifest_digest"], STAGE_DIGEST);
    assert_eq!(
        object["verification_specification_digest"],
        VERIFICATION_SPEC_DIGEST
    );
    assert!(!encoded.to_string().contains("Fix the private regression"));
    assert!(!encoded.to_string().contains("/Users/"));
    assert!(object.get("task").is_none());
    assert!(object.get("workspace_path").is_none());
    Ok(())
}

#[test]
fn safe_external_agents_always_require_exact_approval() -> TestResult {
    for frontend in [Frontend::Cli, Frontend::Tui, Frontend::Telegram] {
        let decision = DefaultPolicy.evaluate(&safe_request(frontend)?);
        assert_eq!(decision.disposition(), PolicyDisposition::Ask);
        assert_eq!(
            decision.reason(),
            PolicyReasonCode::ExternalAgentRequiresApproval
        );
    }
    Ok(())
}

#[test]
fn unsafe_external_agent_capabilities_are_denied_before_approval() -> TestResult {
    let live = request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        true,
    )?;
    let environment = request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::from([EnvironmentGrant::Credential]),
        false,
    )?;
    let network = request_with(
        Frontend::Cli,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::XaiGrok,
        BTreeSet::new(),
        false,
    )?;

    assert_eq!(
        DefaultPolicy.evaluate(&live).reason(),
        PolicyReasonCode::LiveWorkspaceExposure
    );
    assert_eq!(
        DefaultPolicy.evaluate(&environment).reason(),
        PolicyReasonCode::EnvironmentGrantForbidden
    );
    assert_eq!(
        DefaultPolicy.evaluate(&network).reason(),
        PolicyReasonCode::ProviderNetworkMismatch
    );
    assert_eq!(
        [
            DefaultPolicy.evaluate(&live).disposition(),
            DefaultPolicy.evaluate(&environment).disposition(),
            DefaultPolicy.evaluate(&network).disposition(),
        ],
        [PolicyDisposition::Deny; 3]
    );
    Ok(())
}

#[test]
fn policy_values_are_bounded_and_debug_output_is_redacted() -> TestResult {
    assert!(ActorId::parse("").is_err());
    assert!(ActorId::parse("owner with spaces").is_err());
    assert!(ActorId::parse("x".repeat(129)).is_err());
    assert!(Sha256Digest::parse("abc").is_err());
    assert!(Sha256Digest::parse("A".repeat(64)).is_err());
    assert!(
        CapabilityRequest::external_agent(
            "invalid tool",
            ActorIdentity::new(ActorId::parse("local-owner")?, Frontend::Cli),
            session_id("11111111-1111-4111-8111-111111111111")?,
            turn_id("22222222-2222-4222-8222-222222222222")?,
            Sha256Digest::parse(PROMPT_DIGEST)?,
            Sha256Digest::parse(STAGE_DIGEST)?,
            Sha256Digest::parse(VERIFICATION_SPEC_DIGEST)?,
            None,
            None,
            ProviderNetwork::OpenAiCodex,
            BTreeSet::new(),
            false,
        )
        .is_err()
    );

    let request = safe_request(Frontend::Cli)?;
    let debug = format!("{request:?}");
    assert!(!debug.contains("local-owner"));
    assert!(!debug.contains(PROMPT_DIGEST));
    assert!(!debug.contains(STAGE_DIGEST));
    assert!(!debug.contains(VERIFICATION_SPEC_DIGEST));
    assert!(!format!("{:?}", request.digest()).contains(EXPECTED_REQUEST_DIGEST));
    Ok(())
}

fn safe_request(frontend: Frontend) -> Result<CapabilityRequest, Box<dyn Error>> {
    request_with(
        frontend,
        "local-owner",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        PROMPT_DIGEST,
        STAGE_DIGEST,
        Some("gpt-5.6"),
        Some(ReasoningEffort::High),
        ProviderNetwork::OpenAiCodex,
        BTreeSet::new(),
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_with(
    frontend: Frontend,
    actor: &str,
    session: &str,
    turn: &str,
    prompt_digest: &str,
    stage_digest: &str,
    model: Option<&str>,
    effort: Option<ReasoningEffort>,
    network: ProviderNetwork,
    environment_grants: BTreeSet<EnvironmentGrant>,
    live_workspace_writable: bool,
) -> Result<CapabilityRequest, Box<dyn Error>> {
    Ok(CapabilityRequest::external_agent(
        "delegate.codex",
        ActorIdentity::new(ActorId::parse(actor)?, frontend),
        session_id(session)?,
        turn_id(turn)?,
        Sha256Digest::parse(prompt_digest)?,
        Sha256Digest::parse(stage_digest)?,
        Sha256Digest::parse(VERIFICATION_SPEC_DIGEST)?,
        model.map(ModelId::parse).transpose()?,
        effort,
        network,
        environment_grants,
        live_workspace_writable,
    )?)
}

fn session_id(value: &str) -> Result<SessionId, uuid::Error> {
    Ok(SessionId::from_uuid(Uuid::parse_str(value)?))
}

fn turn_id(value: &str) -> Result<TurnId, uuid::Error> {
    Ok(TurnId::from_uuid(Uuid::parse_str(value)?))
}
