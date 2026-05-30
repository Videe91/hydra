//! CausalCell — Patch 20 vocabulary for grouping a reflex chain
//! into a named, durable causal unit.
//!
//! After Patches 1-19, Hydra has many independent reflex chains:
//!
//! ```text
//!   prediction → evidence → claim → action → outcome →
//!   observation → trust
//! ```
//!
//! Patch 20 introduces the primitive that lets Hydra say
//! "this whole chain is one causal unit":
//!
//! ```text
//!   CausalCell { kind: Reflex, subject: "...", source_events,
//!                evidence_ids, claim_ids, action_ids,
//!                outcome_ids, observation_run_ids,
//!                child_cell_ids, trust_score?, summary? }
//! ```
//!
//! ## What Patch 20 is — and isn't
//!
//! Patch 20 is **vocabulary + store + snapshot only**. It adds
//! the type, an `EventKind::CausalCellCreated` event, a store
//! (in `hydra-engine`), and snapshot round-trip support.
//!
//! Patch 20 does **NOT**:
//! - automatically create cells from existing reflex chains
//! - compose cells into bigger cells
//! - fold trust scores up the composition tree
//! - expose HTTP / Python SDK surfaces
//! - run an identity graph or correlation engine
//!
//! Future patches add those layer-by-layer. Patch 20 is the
//! clean first step.

use crate::{
    ActionId, ActorId, CausalCellId, ClaimId, EventId, EvidenceId,
    MicroModelRunId, OutcomeId, TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What a CausalCell represents. PascalCase wire form via serde
/// default — matches every other Hydra enum.
///
/// The most important variant for Patch 20 is `Reflex`. Future
/// patches make `Health`, `Incident`, `Dataset` operationally
/// useful as composition primitives.
///
/// `Custom(String)` is the open-ended escape hatch for
/// deployments that have domain-specific groupings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CausalCellKind {
    /// One reflex chain — the canonical Patch 20 use case.
    Reflex,
    /// Aggregate health-status cell (planned composition target).
    Health,
    /// A single incident / outage / anomaly response.
    Incident,
    /// One dataset's full causal story.
    Dataset,
    /// One agent's bounded activity unit.
    Agent,
    /// One workflow run.
    Workflow,
    /// One external source / ingest pipeline.
    Source,
    /// One tenant's aggregated story.
    Tenant,
    /// One case / investigation thread.
    Case,
    /// Deployment-specific cell type.
    Custom(String),
}

impl CausalCellKind {
    /// Stable snake_case discriminant string. Useful for the
    /// engine's `cells_by_kind` index and for future metrics
    /// labels. `Custom(label)` uses the label directly.
    ///
    /// Why snake_case and not the wire-form PascalCase? Because
    /// the discriminant is for INDEXING and LABELS, not wire
    /// shape. Mirrors `MicroModelKind::discriminant()`.
    pub fn discriminant(&self) -> String {
        match self {
            CausalCellKind::Reflex => "reflex".to_string(),
            CausalCellKind::Health => "health".to_string(),
            CausalCellKind::Incident => "incident".to_string(),
            CausalCellKind::Dataset => "dataset".to_string(),
            CausalCellKind::Agent => "agent".to_string(),
            CausalCellKind::Workflow => "workflow".to_string(),
            CausalCellKind::Source => "source".to_string(),
            CausalCellKind::Tenant => "tenant".to_string(),
            CausalCellKind::Case => "case".to_string(),
            CausalCellKind::Custom(label) => label.clone(),
        }
    }
}

/// A bounded causal unit.
///
/// Patch 20 boundary: this is a passive container. Nothing in
/// the engine creates cells automatically. Callers (operators,
/// future patches) construct a `CausalCell`, hand it to
/// `Hydra::create_causal_cell`, and Hydra records the
/// `CausalCellCreated` event + stores the cell.
///
/// Field semantics:
///
/// - `id` — stable identity; ULID-based.
/// - `tenant_id` — `None` for cross-tenant / system cells.
/// - `kind` + `subject` — coarse classification. `subject` is
///   a free-form string ("hydra.commit-rate", "incident-2026-05-30",
///   etc.) chosen by the caller.
/// - The six id vectors (`source_events`, `evidence_ids`, etc.)
///   group existing Hydra primitives. Empty by default; callers
///   fill in whichever chain elements apply.
/// - `child_cell_ids` — composition primitive. Empty in v0
///   cells; future patches that compose cells populate this.
/// - `trust_score` — `Option<f64>` because trust is computed
///   externally (Patch 9). Future patches that fold trust up
///   the composition tree write here.
/// - `summary` — short prose for dashboards.
/// - `created_by` + `created_at` — provenance.
/// - `caused_by` — optional `EventId` linking the cell back to
///   the originating event (e.g., the prediction event id of
///   the reflex chain this cell wraps). Empty for cells created
///   from no specific trigger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalCell {
    pub id: CausalCellId,
    pub tenant_id: Option<TenantId>,

    pub kind: CausalCellKind,
    pub subject: String,

    pub source_events: Vec<EventId>,
    pub evidence_ids: Vec<EvidenceId>,
    pub claim_ids: Vec<ClaimId>,
    pub action_ids: Vec<ActionId>,
    pub outcome_ids: Vec<OutcomeId>,
    pub observation_run_ids: Vec<MicroModelRunId>,

    pub child_cell_ids: Vec<CausalCellId>,

    pub trust_score: Option<f64>,
    pub summary: Option<String>,

    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub caused_by: Option<EventId>,
}

impl CausalCell {
    /// Construct a minimally-populated cell of a given `kind` +
    /// `subject` with everything else empty. Convenience for
    /// the most common Patch 20 use case (an empty container
    /// the caller will then attach ids to).
    pub fn new(
        kind: CausalCellKind,
        subject: impl Into<String>,
        created_by: ActorId,
    ) -> Self {
        Self {
            id: CausalCellId::new(),
            tenant_id: None,
            kind,
            subject: subject.into(),
            source_events: Vec::new(),
            evidence_ids: Vec::new(),
            claim_ids: Vec::new(),
            action_ids: Vec::new(),
            outcome_ids: Vec::new(),
            observation_run_ids: Vec::new(),
            child_cell_ids: Vec::new(),
            trust_score: None,
            summary: None,
            created_by,
            created_at: Utc::now(),
            caused_by: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causal_cell_kind_serializes_pascal_case() {
        // Pinned so a future `#[serde(rename_all)]` change doesn't
        // silently break the wire contract.
        assert_eq!(
            serde_json::to_string(&CausalCellKind::Reflex).unwrap(),
            "\"Reflex\""
        );
        assert_eq!(
            serde_json::to_string(&CausalCellKind::Health).unwrap(),
            "\"Health\""
        );
        assert_eq!(
            serde_json::to_string(&CausalCellKind::Incident).unwrap(),
            "\"Incident\""
        );
        // Custom uses default serde for unit-with-payload.
        let custom = CausalCellKind::Custom("invoice_anomaly".to_string());
        let json = serde_json::to_string(&custom).unwrap();
        assert_eq!(json, "{\"Custom\":\"invoice_anomaly\"}");
        let parsed: CausalCellKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, custom);
    }

    #[test]
    fn causal_cell_kind_discriminant_returns_snake_case() {
        assert_eq!(CausalCellKind::Reflex.discriminant(), "reflex");
        assert_eq!(CausalCellKind::Health.discriminant(), "health");
        assert_eq!(CausalCellKind::Incident.discriminant(), "incident");
        assert_eq!(CausalCellKind::Dataset.discriminant(), "dataset");
        assert_eq!(CausalCellKind::Agent.discriminant(), "agent");
        assert_eq!(CausalCellKind::Workflow.discriminant(), "workflow");
        assert_eq!(CausalCellKind::Source.discriminant(), "source");
        assert_eq!(CausalCellKind::Tenant.discriminant(), "tenant");
        assert_eq!(CausalCellKind::Case.discriminant(), "case");
        assert_eq!(
            CausalCellKind::Custom("xyz".to_string()).discriminant(),
            "xyz"
        );
    }

    #[test]
    fn causal_cell_id_uses_cell_prefix() {
        let id = CausalCellId::new();
        assert!(
            id.as_str().starts_with("cell_"),
            "expected cell_ prefix, got {}",
            id.as_str()
        );
    }

    #[test]
    fn causal_cell_new_constructs_empty_container() {
        // The convenience constructor: kind + subject + actor →
        // everything else empty. Pin the contract so future
        // additions to `CausalCell` don't silently set non-empty
        // defaults.
        let cell = CausalCell::new(
            CausalCellKind::Reflex,
            "hydra.commit-rate",
            ActorId::from_str("actor_ops"),
        );
        assert_eq!(cell.kind, CausalCellKind::Reflex);
        assert_eq!(cell.subject, "hydra.commit-rate");
        assert!(cell.tenant_id.is_none());
        assert!(cell.source_events.is_empty());
        assert!(cell.evidence_ids.is_empty());
        assert!(cell.claim_ids.is_empty());
        assert!(cell.action_ids.is_empty());
        assert!(cell.outcome_ids.is_empty());
        assert!(cell.observation_run_ids.is_empty());
        assert!(cell.child_cell_ids.is_empty());
        assert!(cell.trust_score.is_none());
        assert!(cell.summary.is_none());
        assert!(cell.caused_by.is_none());
    }

    #[test]
    fn causal_cell_round_trips_through_json() {
        // Pin wire shape — every field must serialize, and a
        // deserialize of the same JSON must recover an equal
        // value.
        let cell = CausalCell {
            id: CausalCellId::from_str("cell_abc"),
            tenant_id: Some(TenantId::from_str("ten_x")),
            kind: CausalCellKind::Reflex,
            subject: "hydra.replication".to_string(),
            source_events: vec![EventId::from_str("evt_1")],
            evidence_ids: vec![EvidenceId::from_str("evd_1")],
            claim_ids: vec![ClaimId::from_str("claim_1")],
            action_ids: vec![ActionId::from_str("act_1")],
            outcome_ids: vec![OutcomeId::from_str("out_1")],
            observation_run_ids: vec![MicroModelRunId::from_str("mmrun_1")],
            child_cell_ids: vec![],
            trust_score: Some(0.92),
            summary: Some("test cell".to_string()),
            created_by: ActorId::from_str("actor_ops"),
            created_at: chrono::DateTime::parse_from_rfc3339(
                "2026-05-30T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
            caused_by: Some(EventId::from_str("evt_origin")),
        };
        let json = serde_json::to_string(&cell).unwrap();
        let parsed: CausalCell = serde_json::from_str(&json).unwrap();
        assert_eq!(cell, parsed);
    }
}
