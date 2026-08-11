mod metrics;
mod scenario;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use metrics::evaluate_release_gate;
pub use scenario::{
    EvaluationScenario, NEEDLE_IDENTIFIER, ScheduledSteering, run_long_horizon_evaluation,
    run_repository_release_gate_matrix, unresolved_started_cut_fails_closed,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationMetrics {
    pub completed: bool,
    pub work_epochs: u32,
    pub provider_requests: u32,
    pub tool_calls: u32,
    pub required_clauses_passed: u32,
    pub duplicate_effects: u32,
    pub lost_identifiers: u32,
    pub out_of_scope_changes: u32,
    pub restarts: u32,
    pub compactions: u32,
    pub strategy_changes: u32,
    pub orphan_processes: u32,
    pub secret_policy_violations: u32,
    pub replay_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub scenario: String,
    pub passed: bool,
    pub metrics: EvaluationMetrics,
    pub failure_codes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvaluationError {
    #[error("the evaluation scenario is invalid")]
    InvalidScenario,
    #[error("the evaluation fixture is unavailable")]
    Fixture,
    #[error("durable evaluation storage failed")]
    Storage,
    #[error("the scripted task engine failed")]
    Engine,
    #[error("the deterministic evaluation invariant failed")]
    Invariant,
}
