pub mod projection;
pub mod registry;
pub mod cascade;
pub mod event_log;
pub mod counterfactual;
pub mod temporal;
pub mod anomaly;
pub mod evolution;
pub mod coverage;
pub mod epistemic_store;
pub mod verification;
pub mod verification_agent;
pub mod action_store;
pub mod policy_store;
pub mod policy_engine;
pub mod policy_agent;
pub mod commit_ledger;
pub mod sensor_checkpoint_store;
pub mod remediation_agent;
pub mod outcome_agent;
pub mod reflex;
pub mod hydra;

/// Convenience re-exports
pub mod prelude {
    pub use crate::projection::Projection;
    pub use crate::registry::SubscriptionRegistry;
    pub use crate::cascade::{CascadeConfig, CascadeEngine, CascadeResult};
    pub use crate::event_log::{EventLog, EventLogConfig};
    pub use crate::counterfactual::{
        counterfactual, counterfactual_filter, diff_projections, impact_score,
        CounterfactualResult, CounterfactualFilterResult,
        GraphDiff, NodeDiff, EdgeDiff, PropertyDiff, ImpactScore,
    };
    pub use crate::temporal::{
        TemporalIndex, TemporalDiff, TemporalNodeChange, TemporalGraphView,
        NodeHistory, EdgeHistory, PropertyVersion, LifecycleVersion,
    };
    pub use crate::anomaly::{
        AnomalyEngine, Anomaly, AnomalyKind, DriftDirection,
        TopologyRule, CascadeRule, DriftRule, ChangeRateRule,
        TimeWindowRule, CounterfactualRule, PatternRule, PropertyPredicate,
    };
    pub use crate::evolution::{
        SubscriptionTracker, SubscriptionMetrics, FireRecord, MissRecord,
        SubscriptionOutcome, MutationProposal, ProposalStatus, FilterSimulation,
    };
    pub use crate::coverage::{
        CoverageEngine, CoverageModel, CoverageExpectation,
        CoverageReport, CoverageGap,
    };
    pub use crate::epistemic_store::{ClaimSubjectKey, EpistemicStore};
    pub use crate::verification::{
        VerificationDecision, VerificationEngine, VerificationPolicy, VerificationReport,
    };
    pub use crate::verification_agent::VerificationAgent;
    pub use crate::action_store::{ActionStore, ActionTargetKey};
    pub use crate::policy_store::{PolicyScopeKey, PolicyStore};
    pub use crate::policy_engine::{
        PolicyEngine, PolicyEvaluationDecision, PolicyEvaluationReport,
    };
    pub use crate::policy_agent::PolicyAgent;
    pub use crate::commit_ledger::{CommitBatchWriter, CommitLedger};
    pub use crate::sensor_checkpoint_store::{
        SensorCheckpointStore, SensorSourceKey, SourceCursorKey,
    };
    pub use crate::remediation_agent::RemediationAgent;
    pub use crate::outcome_agent::OutcomeAgent;
    pub use crate::reflex::{Reflex, ReflexContext, ReflexRegistry};
    pub use crate::hydra::{Hydra, ResourceLimits, WalWriter};
}
