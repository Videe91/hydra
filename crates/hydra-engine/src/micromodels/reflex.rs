//! Shared bridge spine for micro-model reflexes — MicroModel
//! Patch 17 (pure refactor).
//!
//! Patches 1–16 built two independent built-in models on parallel
//! bridge plumbing:
//!
//! ```text
//!   prediction → evidence → claim → (gate) → Notify action
//! ```
//!
//! By the end of Patch 16, the per-model bridge methods in
//! `Hydra` were mechanically identical except for:
//!
//! - the level type (4 vs 3 variants)
//! - the claim's `subject` / `predicate` / `object`
//! - the action's `target`
//! - the evidence + action payload `data` HashMaps
//! - the per-model assessment envelope struct
//!
//! Patch 17 extracts the SHARED spine into this module. The
//! shape is deliberately pragmatic:
//!
//! - No public trait, no generics, no associated types — just
//!   free functions taking `&mut Hydra` and a small parameter
//!   struct.
//! - `pub(crate)` only. The public engine API
//!   (`evaluate_commit_rate_anomaly_*`,
//!   `evaluate_replication_lag_anomaly_*`) keeps bit-identical
//!   signatures and return types. SDK + HTTP unchanged.
//! - Each model owns its own `MicroModelReflexParts`
//!   constructor; this module owns the event-emitting spine.
//!
//! ## What stays per-model (NOT here)
//!
//! - The pure math (`evaluate_observation`) — `commit_rate.rs`
//!   and `replication_lag.rs`.
//! - The input lookup (count commits in window /
//!   `peer.last_lag`) — `Hydra::record_*_prediction`.
//! - The prediction's typed `input` JSON shape — model-specific.
//! - The assessment envelope struct itself — every model wants
//!   its own typed return value, the parts list isn't enough.

use crate::hydra::Hydra;
use hydra_core::{
    action::{Action, ActionKind, ActionStatus, ActionTarget},
    epistemic::{
        Claim, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence,
        Evidence, EvidencePayload, EvidenceSource,
    },
    ActionId, ActorId, ClaimId, EventId, EventKind, EvidenceId,
    MicroModelDefinition, MicroModelId, MicroModelKind, MicroModelPrediction,
    MicroModelStatus, Value,
};
use std::collections::HashMap;

/// Per-model parts that drive the shared bridge helpers.
///
/// Each model converts its `Output` into one of these. The
/// helpers below read it. This is the SHARED data contract — the
/// thing that makes per-model variation expressible without a
/// trait.
///
/// `actionable` mirrors each model's own actionable-level
/// vocabulary (commit-rate's `is_actionable()`, replication-lag's
/// `is_actionable()` — both true for Warning + Critical).
/// `confidence` is currently always the prediction's confidence,
/// but is carried separately so a future model can decouple
/// claim confidence from prediction confidence.
pub(crate) struct MicroModelReflexParts {
    pub actionable: bool,
    pub confidence: f64,

    // Claim shape.
    pub claim_subject: ClaimSubject,
    pub claim_predicate: String,
    pub claim_object: ClaimObject,

    /// Body of `EvidencePayload.data`. `EvidencePayload.kind` is
    /// fixed to `"micro_model_prediction"` for all reflex models.
    pub evidence_payload_data: HashMap<String, Value>,

    pub action_target: ActionTarget,
    pub action_payload: HashMap<String, Value>,
}

/// Ids surfaced after the shared bridge fires Evidence + Claim.
/// `None` from `propose_claim_from_reflex` means the model wasn't
/// actionable; in that case no bridge ids exist.
pub(crate) struct ReflexBridgeIds {
    pub evidence_id: EvidenceId,
    pub evidence_event_id: EventId,
    pub claim_id: ClaimId,
    pub claim_event_id: EventId,
}

/// Auto-register a built-in micro-model definition if it isn't
/// in the registry yet, and promote it to `Active`. Idempotent.
///
/// Patch 17 extraction of the auto-register block that was
/// previously duplicated inside `record_commit_rate_prediction`
/// and `record_replication_lag_prediction`.
pub(crate) fn ensure_builtin_model_registered(
    hydra: &mut Hydra,
    model_id: &MicroModelId,
    kind: MicroModelKind,
    name: &str,
    actor_id: &ActorId,
) -> hydra_core::error::Result<()> {
    if hydra.micro_model(model_id).is_some() {
        return Ok(());
    }
    let now = chrono::Utc::now();
    let definition = MicroModelDefinition::registered(
        model_id.clone(),
        kind,
        name,
        1,
        vec![],
        vec![],
        actor_id.clone(),
        now,
    );
    hydra.register_micro_model(definition)?;
    hydra.change_micro_model_status(
        model_id.clone(),
        MicroModelStatus::Active,
        Some("built-in micro-model: active on register".to_string()),
    )?;
    Ok(())
}

/// Build + ingest Evidence + Claim from a model prediction, but
/// only when `parts.actionable == true`. Returns `Ok(None)` on
/// the non-actionable path so callers can short-circuit the
/// action bridge too.
///
/// The Claim's `caused_by` points at the PREDICTION event, NOT
/// at the Evidence event — this preserves the prior chain shape
/// `prediction → evidence + claim → action`.
pub(crate) fn propose_claim_from_reflex(
    hydra: &mut Hydra,
    prediction: &MicroModelPrediction,
    prediction_event_id: EventId,
    parts: &MicroModelReflexParts,
    actor: ActorId,
) -> hydra_core::error::Result<Option<ReflexBridgeIds>> {
    if !parts.actionable {
        return Ok(None);
    }

    // Build + ingest Evidence first so the Claim can reference
    // its id in `evidence_for`.
    let evidence = Evidence {
        id: EvidenceId::new(),
        tenant_id: None,
        source: EvidenceSource::System {
            name: prediction.model_id.as_str().to_string(),
        },
        payload: EvidencePayload {
            kind: "micro_model_prediction".to_string(),
            data: parts.evidence_payload_data.clone(),
        },
        reliability: Confidence::new(prediction.confidence),
        observed_at: prediction.created_at,
        recorded_at: prediction.created_at,
        caused_by: Some(prediction_event_id.clone()),
    };
    let evidence_id = evidence.id.clone();
    let evidence_cascade =
        hydra.ingest(EventKind::EvidenceAdded { evidence })?;
    let evidence_event_id = evidence_cascade
        .events
        .first()
        .map(|event| event.id.clone())
        .expect(
            "ingest produces at least the trigger event for EvidenceAdded",
        );

    let claim = Claim {
        id: ClaimId::new(),
        tenant_id: None,
        kind: ClaimKind::AnomalyFinding,
        subject: parts.claim_subject.clone(),
        predicate: parts.claim_predicate.clone(),
        object: parts.claim_object.clone(),
        confidence: Confidence::new(parts.confidence),
        status: ClaimStatus::Proposed,
        evidence_for: vec![evidence_id.clone()],
        evidence_against: vec![],
        valid_from: prediction.created_at,
        valid_until: None,
        created_by: actor,
        created_at: prediction.created_at,
        updated_at: prediction.created_at,
        caused_by: Some(prediction_event_id),
    };
    let claim_id = claim.id.clone();
    let claim_cascade =
        hydra.ingest(EventKind::ClaimProposed { claim })?;
    let claim_event_id = claim_cascade
        .events
        .first()
        .map(|event| event.id.clone())
        .expect(
            "ingest produces at least the trigger event for ClaimProposed",
        );

    Ok(Some(ReflexBridgeIds {
        evidence_id,
        evidence_event_id,
        claim_id,
        claim_event_id,
    }))
}

/// Re-read the claim, run the v0 verification gate
/// (`claim.predicate == parts.claim_predicate AND
/// (status == Verified OR confidence >= 0.9)`), and build +
/// ingest a Notify action when the gate passes.
///
/// The re-read is load-bearing: the verification cascade may
/// have promoted the just-ingested Claim from Proposed → Verified
/// in the same cascade as `ClaimProposed`, so reading the
/// post-cascade state is the only honest gate check.
pub(crate) fn propose_action_from_reflex(
    hydra: &mut Hydra,
    prediction: &MicroModelPrediction,
    bridge: &ReflexBridgeIds,
    parts: &MicroModelReflexParts,
    actor: ActorId,
) -> hydra_core::error::Result<Option<ActionId>> {
    let passes_gate = hydra
        .claim(&bridge.claim_id)
        .map(|claim| {
            claim.predicate == parts.claim_predicate
                && (claim.status == ClaimStatus::Verified
                    || claim.confidence.value() >= 0.9)
        })
        .unwrap_or(false);
    if !passes_gate {
        return Ok(None);
    }

    let action = Action {
        id: ActionId::new(),
        tenant_id: None,
        kind: ActionKind::Notify,
        status: ActionStatus::Proposed,
        targets: vec![parts.action_target.clone()],
        related_claims: vec![bridge.claim_id.clone()],
        supporting_evidence: vec![bridge.evidence_id.clone()],
        proposed_by: actor,
        approved_by: None,
        rejected_by: None,
        // No policy DSL in v0. The action's inline gate fired it,
        // not a registered Policy record.
        policy_id: None,
        payload: parts.action_payload.clone(),
        created_at: prediction.created_at,
        updated_at: prediction.created_at,
        approved_at: None,
        rejected_at: None,
        executed_at: None,
        caused_by: Some(bridge.claim_event_id.clone()),
    };
    let action_id = action.id.clone();
    hydra.ingest(EventKind::ActionProposed { action })?;
    Ok(Some(action_id))
}
