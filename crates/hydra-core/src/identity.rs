//! Identity Graph vocabulary — Patch 29.
//!
//! An `IdentityEntity` is the canonical name for a real-world or
//! system object (a dataset, a service, a user, a workflow) onto
//! which many source-specific names map. The classic example:
//!
//! ```text
//! Snowflake: ANALYTICS.REVENUE_DAILY
//! dbt:       model.analytics.revenue_daily
//! Looker:    Revenue Daily Dashboard
//! GitHub:    models/revenue_daily.sql
//! Slack:     "revenue dashboard"
//!
//! → IdentityEntity { kind: Dataset, canonical_key: "dataset/revenue_daily" }
//! ```
//!
//! Patch 29 ships vocabulary + store + event replay + snapshot.
//! No matching, no correlation, no HTTP/SDK, no links — those
//! land in later patches (P30+).
//!
//! ## Identities are immutable in v0
//!
//! Mirrors the `CausalCell` v0 model (Patch 20). One event variant
//! — `EventKind::IdentityEntityCreated`. Updates / merges / deletes
//! are explicit future patches. If you need to change an entity's
//! aliases today, create a new entity. The cost of fast-iteration
//! immutability is occasional duplication; the benefit is replay
//! semantics that are dead simple.
//!
//! ## Aliases are embedded, not separate events
//!
//! `IdentityEntity.aliases: Vec<IdentityAlias>` is the source-of-
//! truth. The store's `by_alias` index keys on
//! `IdentityAlias::index_key(tenant)` so a single alias resolution
//! is an O(1) hash lookup.
//!
//! ## Identity vs other Hydra concepts
//!
//! `IdentityEntityKind` deliberately overlaps with several existing
//! concepts. They are NOT the same:
//!
//! - `IdentityEntityKind::User` ≠ `ActorId`. An entity of kind
//!   `User` is the canonical real-world person (e.g.,
//!   "alice@acme.com"); `ActorId`s on events reference humans,
//!   service accounts, and bots interchangeably. Future
//!   correlation links `ActorId` → `IdentityEntity`.
//!
//! - `IdentityEntityKind::Dataset` ≠ `ClaimSubject::Dataset(s)`.
//!   The former is a canonical durable handle; the latter is a
//!   free-form string on a claim. Future correlation lets a
//!   claim's dataset subject resolve to an `IdentityEntity`.
//!
//! - `IdentityEntityKind::System` ≠ `ClaimSubject::System(s)`.
//!   Same pattern.
//!
//! In short: identity entities are canonical semantic objects.
//! `ActorId`s and `ClaimSubject` strings are event-level
//! references that may or may not resolve to one yet.

use crate::event::Value;
use crate::id::{
    ActorId, CausalCellId, ClaimId, EventId, EvidenceId, IdentityEntityId,
    IdentityLinkId, TenantId,
};
use crate::epistemic::Confidence;
use crate::trust::TrustFactor;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// What an `IdentityEntity` represents. PascalCase wire form via
/// serde default — matches every other Hydra enum. The
/// `Custom(String)` variant is the open-ended escape hatch for
/// deployment-specific entity types.
///
/// The variant set is intentionally broad — identity is a cross-
/// cutting concern that must work for the data plane (datasets,
/// tables, metrics), the operational plane (services, agents,
/// workflows), and the people plane (users, systems, incidents).
/// Future sensors can lean on `Custom(label)` without needing a
/// new variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityEntityKind {
    /// A logical dataset / data product (e.g., "revenue_daily").
    /// Distinct from `ClaimSubject::Dataset` — that's a free-form
    /// string; this is a canonical handle.
    Dataset,
    /// A specific physical table backing a dataset.
    Table,
    /// A dashboard / report / view.
    Dashboard,
    /// A metric / KPI / measure.
    Metric,
    /// A service / API / micro-component.
    Service,
    /// An agent (data-quality, observability, model-derived, etc.).
    /// Distinct from `ActorId` — that's an event-level reference;
    /// this is the canonical identity behind it.
    Agent,
    /// A workflow / pipeline / DAG.
    Workflow,
    /// An external source / ingest pipeline (Snowflake, Postgres,
    /// Kafka, GitHub, etc.).
    Source,
    /// A real-world user / person. Distinct from `ActorId`.
    User,
    /// A system component — distinct from `ClaimSubject::System`.
    System,
    /// An incident / outage / case.
    Incident,
    /// Deployment-specific entity type.
    Custom(String),
}

impl IdentityEntityKind {
    /// Stable snake_case discriminant string. Used by
    /// `IdentityStore::by_kind` indexing so the `Custom(_)`
    /// variant doesn't need an `Ord` impl. Mirrors the
    /// `CausalCellKind::discriminant()` pattern from Patch 20.
    pub fn discriminant(&self) -> String {
        match self {
            IdentityEntityKind::Dataset => "dataset".to_string(),
            IdentityEntityKind::Table => "table".to_string(),
            IdentityEntityKind::Dashboard => "dashboard".to_string(),
            IdentityEntityKind::Metric => "metric".to_string(),
            IdentityEntityKind::Service => "service".to_string(),
            IdentityEntityKind::Agent => "agent".to_string(),
            IdentityEntityKind::Workflow => "workflow".to_string(),
            IdentityEntityKind::Source => "source".to_string(),
            IdentityEntityKind::User => "user".to_string(),
            IdentityEntityKind::System => "system".to_string(),
            IdentityEntityKind::Incident => "incident".to_string(),
            IdentityEntityKind::Custom(label) => label.clone(),
        }
    }
}

/// Reserved sentinel for `None` tenant in `IdentityAlias::index_key`.
/// Internal — inputs matching this exactly will be rejected by
/// validation to prevent key collisions.
pub(crate) const ALIAS_TENANT_NONE_SENTINEL: &str = "__system__";

/// Reserved sentinel for `None` namespace in
/// `IdentityAlias::index_key`. Same rationale as the tenant
/// sentinel — never accept user input that matches.
pub(crate) const ALIAS_NAMESPACE_NONE_SENTINEL: &str = "__root__";

/// A source-specific name for an `IdentityEntity`.
///
/// Each connector or sensor speaks its own dialect of names for
/// the same real-world thing. An `IdentityAlias` records one
/// such name so Hydra can later round-trip back to the source
/// (`external_id`) AND resolve the alias to its canonical entity
/// (`normalized`).
///
/// Field semantics:
///
/// - `source` — non-empty identifier of the system that owns
///   this name (`"snowflake"`, `"github"`, `"dbt"`, `"looker"`).
///   Lowercase by convention but unenforced.
/// - `namespace` — source-specific scope (a Snowflake database,
///   a GitHub repo path, etc.). `None` for sources without a
///   namespace concept.
/// - `external_id` — the source's own stable id, for round-trip
///   lookups. May be `None` if the source only exposes a label
///   (e.g., Slack channel name).
/// - `label` — human-readable display string for this alias.
/// - `normalized` — lowercased + canonicalized form used for
///   matching. `"ANALYTICS.REVENUE_DAILY"` and
///   `"analytics.revenue_daily"` should produce the same
///   `normalized` so they resolve to the same canonical entity.
///   This is what `index_key` keys on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityAlias {
    pub source: String,
    pub namespace: Option<String>,
    pub external_id: Option<String>,
    pub label: String,
    pub normalized: String,
}

impl IdentityAlias {
    /// Stable canonical index key used by `IdentityStore::by_alias`.
    ///
    /// Composes the four uniqueness inputs into one string with a
    /// reserved `__system__` sentinel for `None` tenant and
    /// `__root__` for `None` namespace. The sentinels are
    /// distinct from any well-formed input (and validation
    /// rejects user-supplied values matching them) so two
    /// semantically-different alias tuples can never produce the
    /// same key.
    ///
    /// Format:
    /// ```text
    ///   "{tenant_or_sentinel}|{source}|{namespace_or_sentinel}|{normalized}"
    /// ```
    pub fn index_key(&self, tenant: Option<&TenantId>) -> String {
        format!(
            "{}|{}|{}|{}",
            tenant
                .map(|t| t.as_str())
                .unwrap_or(ALIAS_TENANT_NONE_SENTINEL),
            self.source,
            self.namespace
                .as_deref()
                .unwrap_or(ALIAS_NAMESPACE_NONE_SENTINEL),
            self.normalized,
        )
    }

    /// Validate that none of the input fields collide with the
    /// reserved sentinels. Called by
    /// `Hydra::create_identity_entity` so a caller can't smuggle
    /// `"__system__"` as a source name and force a key collision
    /// with the `None`-tenant slot.
    pub fn validate(&self) -> Result<(), String> {
        if self.source == ALIAS_TENANT_NONE_SENTINEL
            || self.source == ALIAS_NAMESPACE_NONE_SENTINEL
        {
            return Err(format!(
                "alias source cannot use reserved sentinel: {}",
                self.source
            ));
        }
        if self.source.is_empty() {
            return Err("alias source cannot be empty".to_string());
        }
        if self.normalized.is_empty() {
            return Err("alias normalized cannot be empty".to_string());
        }
        if let Some(ns) = self.namespace.as_deref() {
            if ns == ALIAS_TENANT_NONE_SENTINEL
                || ns == ALIAS_NAMESPACE_NONE_SENTINEL
            {
                return Err(format!(
                    "alias namespace cannot use reserved sentinel: {ns}",
                ));
            }
        }
        Ok(())
    }
}

/// A canonical identity entity.
///
/// Patch 29 boundary: a passive container. Hydra records
/// `EventKind::IdentityEntityCreated`, stores the entity, and
/// indexes its aliases. Nothing in the engine creates entities
/// automatically. Callers (operators today, future sensors)
/// construct an `IdentityEntity`, hand it to
/// `Hydra::create_identity_entity`, and Hydra ingests the event +
/// validates uniqueness.
///
/// Field semantics:
///
/// - `id` — stable identity; ULID-based with `ide_` prefix.
/// - `tenant_id` — `None` for cross-tenant / system entities.
///   Strict isolation: `None`-tenanted entities are invisible to
///   tenanted lookups via `Hydra::identity_entity_by_alias`.
/// - `kind` + `canonical_key` + `display_name` — the canonical
///   handle (`kind` = `Dataset`, `canonical_key` =
///   `"dataset/revenue_daily"`, `display_name` =
///   `"Revenue (daily)"`).
/// - `aliases` — embedded list of source-specific names.
/// - `confidence` — how confident Hydra is that this alias
///   bundle refers to one canonical thing. `1.0` for operator-
///   declared entities; lower scores for future auto-resolved
///   entities (Patch 30+).
/// - `metadata` — free-form bag for future schema additions
///   without breaking the wire shape.
/// - `created_by` + `created_at` + `updated_at` + `caused_by` —
///   audit trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityEntity {
    pub id: IdentityEntityId,
    pub tenant_id: Option<TenantId>,

    pub kind: IdentityEntityKind,
    pub canonical_key: String,
    pub display_name: String,

    pub aliases: Vec<IdentityAlias>,

    pub confidence: Confidence,
    pub metadata: HashMap<String, Value>,

    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub caused_by: Option<EventId>,
}

// === Patch 30 — Semantic Identity Resolution v1 ===================
//
// Suggestion-only matcher types. Patch 30 ships an engine method
// `Hydra::suggest_identity_matches` that scores existing
// `IdentityEntity`s against a query alias using deterministic
// factor-based weights — same explainability shape as
// `TrustAssessment` (P9) and `CausalCellTrustAssessment` (P23).
//
// **Suggestion-only by design.** The weights are calibrated for
// EXPLAINABILITY, not guaranteed correctness — false positives
// are expected (e.g., `revenue_daily` matching
// `revenue_daily_archived` via token overlap). Any future patch
// that auto-links / auto-merges based on these scores MUST add a
// separate trust gate (mirror Patch 11's `read:trust +
// write:execute` pattern), gate on `MatchLevel::Strong`, and
// require a configured minimum score floor.

/// Match strength for a candidate identity.
///
/// Distinct vocabulary from `TrustLevel` because "trust" and
/// "match" are different concepts (you can have a high-trust
/// mismatch). Shares the numeric threshold table for
/// consistency with claim trust + cell trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchLevel {
    /// Score ≥ 0.80. Very likely the same canonical thing.
    Strong,
    /// Score ≥ 0.50. Operator should compare.
    Possible,
    /// Score ≥ 0.20. Weak signal — usually a false positive
    /// driven by shared tokens or same source. Worth surfacing
    /// only when no Strong/Possible candidate exists.
    Weak,
    /// Score < 0.20. Effectively no match.
    None,
}

impl MatchLevel {
    /// Bucket a clamped `[0.0, 1.0]` score into a `MatchLevel`.
    /// Uses the same numeric thresholds as
    /// `TrustAssessment::level_for_score` so operators see a
    /// consistent scale across trust + match dashboards.
    pub fn level_for_score(score: f64) -> MatchLevel {
        if score >= 0.80 {
            MatchLevel::Strong
        } else if score >= 0.50 {
            MatchLevel::Possible
        } else if score >= 0.20 {
            MatchLevel::Weak
        } else {
            MatchLevel::None
        }
    }
}

/// One scored candidate entity within a
/// `SemanticIdentityMatchAssessment`.
///
/// `score` is the sum of `applied=true` factor weights clamped
/// to `[0.0, 1.0]`. `level` is computed from `score` via
/// `MatchLevel::level_for_score`. `factors` includes ALL
/// evaluated factors — applied AND unapplied — same contract as
/// P9/P23 trust assessments so the explanation is honest about
/// what was checked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticIdentityMatchCandidate {
    pub entity_id: IdentityEntityId,
    pub score: f64,
    pub level: MatchLevel,
    pub factors: Vec<TrustFactor>,
}

/// Read-only result of `Hydra::suggest_identity_matches`.
///
/// `query_alias` is the input alias being resolved. `candidates`
/// are the top N entities sorted by score descending, then by
/// `entity_id` ascending for stable ordering. Candidates with
/// score 0.0 are excluded so the list is always actionable.
///
/// **Suggestion-only.** No mutation, no persistence, no events.
/// See the module-level warning before building anything that
/// auto-acts on this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticIdentityMatchAssessment {
    pub query_alias: IdentityAlias,
    pub candidates: Vec<SemanticIdentityMatchCandidate>,
    pub assessed_at: DateTime<Utc>,
}

// === Patch 32 — Identity Match Trust ============================
//
// Read-only trust verdict over a single P30 semantic-match
// candidate. Distinct vocabulary axis from `MatchLevel`:
//
//   MatchLevel : "how strongly do these names resemble each other?"
//   TrustLevel : "do I trust the resemblance enough to act on it?"
//
// `match_score` + `match_level` are passed through from P30
// verbatim so the caller sees both signals. `score` + `level`
// are the P32 verdict (clamped sum of factors). `factors`
// includes ALL evaluated factors (applied + unapplied) — same
// explainability contract as P9 / P23 / P30.
//
// **Suggestion-only contract carries forward.** See the
// `assess_identity_match_trust` docstring on the engine method
// for the full warning. Trust factors inherit P30's positive-
// only weight calibration; a `semantic_match_strong` factor
// can fire for `revenue_daily ↔ revenue_daily_archived` as
// readily as a true match. Operators must judge each verdict;
// any future auto-link MUST add a separate trust gate, require
// `TrustLevel::High`, require a minimum score floor, AND emit
// a durable `IdentityLink` event for audit.

/// One trust verdict over a (query alias, candidate entity)
/// pair, produced by `Hydra::assess_identity_match_trust`.
///
/// Field semantics:
///
/// - `query_alias` — the alias being assessed (echoed back).
/// - `candidate_entity_id` — the entity being judged against.
/// - `match_score` / `match_level` — pass-through from P30's
///   semantic scoring on this candidate alone (recomputed
///   live; never accepted from the caller). `match_level` uses
///   `MatchLevel` PascalCase wire (including the literal
///   string `"None"` for no semantic match).
/// - `score` — P32 trust score, clamped to `[0.0, 1.0]`. Sum
///   of applied factor weights; can dip below 0 pre-clamp
///   when penalties dominate.
/// - `level` — `TrustLevel` bucket of `score` via
///   `TrustAssessment::level_for_score` (≥0.80 High, ≥0.50
///   Medium, ≥0.20 Low, else Unknown — shared with claim/cell
///   trust).
/// - `explanation` — short prose for dashboards.
/// - `factors` — ALL evaluated factors. Don't filter
///   `applied=false` client-side; the explanation is what was
///   checked, not just what fired.
/// - `assessed_at` — wall-clock at compute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityMatchTrustAssessment {
    pub query_alias: IdentityAlias,
    pub candidate_entity_id: IdentityEntityId,
    pub match_score: f64,
    pub match_level: MatchLevel,
    pub score: f64,
    pub level: crate::trust::TrustLevel,
    pub explanation: String,
    pub factors: Vec<TrustFactor>,
    pub assessed_at: DateTime<Utc>,
}

// === Patch 33 — Identity Entity Trust v1 ===========================
//
// Read-only verdict over the IDENTITY RECORD ITSELF — distinct
// from P32's match-axis trust. Different question:
//
//   P30  : how strongly do these names resemble each other?
//   P32  : do I trust THIS alias→entity match?
//   P33  : do I trust the canonical entity RECORD as a stable
//          identity object?
//
// v1 uses ONLY entity-internal signals — `confidence`,
// `aliases`, `canonical_key`, `display_name`, `metadata`. It
// does NOT consult related claims, cells, observations, source
// reliability, or external evidence. Those layer on in P35+
// (after `IdentityLink` connects the identity graph to other
// Hydra primitives).
//
// **A High verdict means "this identity record is well-formed
// and consistent with P29 invariants"**, NOT "every operational
// fact about this entity is trustworthy." Future auto-actions
// MUST gate on `TrustLevel::High` + minimum score floor + emit
// a separate audit event.

/// Trust verdict over an `IdentityEntity` as an identity
/// record. Produced by `Hydra::assess_identity_entity_trust`.
///
/// Field semantics:
///
/// - `entity_id` — the entity being judged.
/// - `score` — P33 trust score, clamped to `[0.0, 1.0]`. Sum
///   of applied factor weights; can dip below 0 pre-clamp
///   when penalties dominate. Maximum reachable in v1 is
///   `0.85` (positive ceiling — see factor table in
///   `assess_identity_entity_trust`).
/// - `level` — `TrustLevel` bucket of `score` via
///   `TrustAssessment::level_for_score` (≥0.80 High, ≥0.50
///   Medium, ≥0.20 Low, else Unknown — shared with claim/cell
///   trust + identity match trust).
/// - `explanation` — short prose summary for dashboards.
/// - `factors` — ALL 12 evaluated factors (applied AND
///   unapplied — same explainability contract as P9 / P23 /
///   P30 / P32). The 6 alias-related factor records appear
///   regardless of whether the entity has aliases, but mark
///   `applied=false` with a "no aliases" detail when the
///   entity carries none.
/// - `assessed_at` — wall-clock at compute.
///
/// **No `related_claim_ids` or `related_cell_ids`** in v1.
/// Those would imply behavior the assessment does NOT compute.
/// They land in P35+ when `IdentityLink` connects the identity
/// graph to claims and cells.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityEntityTrustAssessment {
    pub entity_id: IdentityEntityId,
    pub score: f64,
    pub level: crate::trust::TrustLevel,
    pub explanation: String,
    pub factors: Vec<TrustFactor>,
    pub assessed_at: DateTime<Utc>,
}

// === Patch 35 — Source Trust v1 ===================================
//
// Read-only verdict over a *source* — the free-form `source` string
// carried on each `IdentityAlias` (e.g. "snowflake", "github",
// "dbt", "agent_data_quality"). Different question from P32 / P33:
//
//   P30  : how strongly do these names resemble each other?
//   P32  : do I trust THIS alias→entity match?
//   P33  : do I trust the canonical entity RECORD as a stable
//          identity object?
//   P35  : do I trust THIS SOURCE as a producer of identity /
//          evidence signals?
//
// **Source trust is identity-backed, NOT operational.** v1 measures
// whether a source has produced trustworthy *identity claims* in
// this tenant — entity count, kind diversity, entity-confidence
// corroboration (via P33), and evidence reliability where the
// mapping from `EvidenceSource` to the source string is
// unambiguous. v1 does NOT consider ingestion freshness, schema
// drift, heartbeat liveness, SLA conformance, contradiction rate
// over time, or operator override history.
//
// A dead Snowflake warehouse with five trustworthy historical
// entities will score **High** here — correct for "did Snowflake
// produce trustworthy identity claims," wrong for "is Snowflake
// alive." Those operational signals layer on in P38+ when
// connector primitives ship.

/// Trust verdict over a source as a producer of identity / evidence
/// signals. Produced by `Hydra::assess_source_trust`.
///
/// Field semantics:
///
/// - `source` — the source string under judgement. Compared via
///   exact string match against `IdentityAlias::source` (P35 does
///   NOT case-fold or normalize — `"snowflake"` and `"Snowflake"`
///   are distinct sources). Sentinel inputs (`""`, `"__system__"`,
///   `"__root__"`) are rejected at the engine boundary as
///   `QueryError`.
/// - `score` — P35 trust score, clamped to `[0.0, 1.0]`. Sum of
///   applied factor weights; can dip below 0 pre-clamp when
///   penalties dominate. Maximum reachable in v1 is `0.80`
///   (positive ceiling — see factor table in `assess_source_trust`).
/// - `level` — `TrustLevel` bucket of `score` via
///   `TrustAssessment::level_for_score` (≥0.80 High, ≥0.50 Medium,
///   ≥0.20 Low, else Unknown — shared with claim / cell / identity
///   trust).
/// - `explanation` — short prose summary for dashboards.
/// - `factors` — ALL evaluated factors (applied AND unapplied —
///   same explainability contract as P9 / P23 / P30 / P32 / P33).
/// - `related_entity_ids` — the entity ids whose aliases reference
///   this source AND were folded into the assessment. Sorted by
///   entity id ascending for deterministic output regardless of
///   the internal sampling order. When the source has more
///   entities than `MAX_SOURCE_ENTITIES_FOR_TRUST`, this list
///   contains the (highest-confidence first) sample — paired with
///   `entity_sample_size`, operators can detect a capped verdict.
/// - `entity_sample_size` — how many entities were folded into the
///   `*_trust_entities_from_source` factor calculation. Capped by
///   `MAX_SOURCE_ENTITIES_FOR_TRUST` (highest-confidence first);
///   the cap is documented and pinned by test so operators know
///   when they're seeing a sampled verdict. Always equal to
///   `related_entity_ids.len()` — kept distinct from the list for
///   symmetry with `evidence_sample_size` (which has no `_ids`
///   counterpart because evidence cardinality is much higher).
/// - `evidence_sample_size` — how many `Evidence` records mapped
///   cleanly to this source (`Warehouse.system`, `Api.system`,
///   `System.name`). Ambiguous variants (`Document`, `Human`,
///   `Agent`) are skipped — see `assess_source_trust` doc.
/// - `assessed_at` — wall-clock at compute.
///
/// **Unknown-but-valid source** (no aliases or evidence reference
/// it) is a legitimate `Unknown` verdict, NOT an error. The empty
/// outcome is surfaced via `explanation`. Only malformed input —
/// empty or sentinel `source` — produces `QueryError`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceTrustAssessment {
    pub source: String,
    pub score: f64,
    pub level: crate::trust::TrustLevel,
    pub explanation: String,
    pub factors: Vec<TrustFactor>,
    pub related_entity_ids: Vec<IdentityEntityId>,
    pub entity_sample_size: usize,
    pub evidence_sample_size: usize,
    pub assessed_at: DateTime<Utc>,
}

// === Patch 37 — IdentityLink vocabulary ============================
//
// IdentityLink turns the Identity Graph from a canonical entity
// REGISTRY into a SEMANTIC RELATIONSHIP GRAPH. An `IdentityLink`
// is a durable directed assertion that two `IdentityEntity` rows
// stand in a specific relationship — a Snowflake table that a dbt
// model `depends_on`, a Looker dashboard that is `downstream_of`
// a dataset, a service that `owned_by` a team entity, two
// canonical entities accidentally minted as separate that are in
// fact `same_as` each other.
//
// ## Suggestion-only contract (mirrors P30 / P32 / P33 / P35)
//
// **IdentityLink is a DURABLE assertion: once created it becomes
// Hydra's standing belief, projected into every snapshot and
// replayed on recovery.**
//
// v0 has:
//
// - **NO trust verdict over the link itself.** The `confidence`
//   field is what the link author believes; it is informational
//   only. Auto-actions MUST gate on a future
//   `IdentityLinkTrustAssessment` (P38+), NOT on raw confidence.
//   Mirrors the P30 suggestion-only contract.
// - **NO automated link inference.** Every link arrives via
//   explicit `Hydra::create_identity_link` from a caller
//   responsible for correctness.
// - **NO update or delete.** Wrong links are corrected by
//   creating a NEW link with corrected semantics; the wrong link
//   remains in the audit log forever. This is append-only
//   assertion, not editable records.
// - **NO referential integrity** on `evidence_ids`, `claim_ids`,
//   `cell_ids`. These are opaque audit references; v0 does not
//   validate that the referenced ids exist.
// - **NO cycle prevention.** Real-world cycles are legitimate
//   (mutual `DependsOn` between micro-services; future
//   Correlation Engine reasons about SCCs).
// - **NO graph projection.** `IdentityLink` lives in
//   `IdentityLinkStore` only; not minted as `Edge` in v0 (mirrors
//   P20 CausalCell + P29 IdentityEntity).
//
// `SameAs` is logically symmetric but stored directionally;
// callers should NOT assume the reverse edge exists. Reverse
// traversal is a query-side concern.
//
// Strict tenant equality applies to `(link, from, to)` — all
// three must agree, including `None == None`. Tenant mismatches
// surface as `"unknown identity entity"` to prevent cross-tenant
// existence enumeration (mirrors P32 indistinguishable-error
// pattern).

/// Kind of `IdentityLink`. PascalCase wire form via serde default
/// — matches `IdentityEntityKind` and every other Hydra enum.
///
/// The 10 built-in kinds cover the common semantic relationships
/// observed in data + operational lineage. `Custom(String)` is
/// the open-ended escape hatch; the label MUST pass
/// `IdentityLinkKind::validate` (no empty, no reserved sentinels,
/// no collision with built-in discriminants).
///
/// Distinction from `IdentityAlias` (P29): an alias is a label
/// stored ON an entity (intra-entity, the entity's name in some
/// source); `SameAs` is a link BETWEEN two distinct canonical
/// entities (inter-entity, two entities accidentally minted as
/// separate that represent the same real thing).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IdentityLinkKind {
    /// Two distinct canonical entities represent the same real
    /// thing. Logically symmetric but stored directionally —
    /// callers do NOT get an auto-mirrored reverse edge.
    SameAs,
    /// Source entity depends on the target (build-time / runtime
    /// dependency). e.g., a dbt model `DependsOn` a Snowflake
    /// table.
    DependsOn,
    /// Source entity is downstream of the target in a lineage
    /// chain. e.g., a Looker dashboard `DownstreamOf` a dbt
    /// model.
    DownstreamOf,
    /// Source entity is owned by the target (team, service
    /// account, user, organizational unit). e.g., a service
    /// `OwnedBy` a User/team entity.
    OwnedBy,
    /// Source entity is produced by the target (writer
    /// relationship). e.g., a dataset `ProducedBy` a workflow.
    ProducedBy,
    /// Source entity is consumed by the target (reader
    /// relationship). e.g., a dataset `ConsumedBy` a dashboard.
    ConsumedBy,
    /// Source entity is derived from the target (transformation
    /// / projection / aggregation). e.g., a metric
    /// `DerivedFrom` a base table.
    DerivedFrom,
    /// Source entity was observed in the context of the target
    /// (telemetry / log / span). e.g., an error `ObservedIn` a
    /// service.
    ObservedIn,
    /// Source entity is part of the target (containment, NOT
    /// dependency). e.g., a column `PartOf` a table; a service
    /// `PartOf` a system.
    PartOf,
    /// Source entity has a relationship to the target that
    /// doesn't fit the more specific kinds. Soft fallback —
    /// prefer a specific kind when one applies.
    RelatedTo,
    /// Open-ended escape hatch. Label MUST pass `validate()`:
    /// non-empty, not a reserved sentinel (`__system__`,
    /// `__root__`), and not a collision with a built-in
    /// discriminant.
    Custom(String),
}

impl IdentityLinkKind {
    /// snake_case discriminant string used by `IdentityLinkStore`
    /// indexes and the `by_pair_kind` dedup key. Mirrors
    /// `IdentityEntityKind::discriminant`.
    pub fn discriminant(&self) -> String {
        match self {
            Self::SameAs => "same_as".to_string(),
            Self::DependsOn => "depends_on".to_string(),
            Self::DownstreamOf => "downstream_of".to_string(),
            Self::OwnedBy => "owned_by".to_string(),
            Self::ProducedBy => "produced_by".to_string(),
            Self::ConsumedBy => "consumed_by".to_string(),
            Self::DerivedFrom => "derived_from".to_string(),
            Self::ObservedIn => "observed_in".to_string(),
            Self::PartOf => "part_of".to_string(),
            Self::RelatedTo => "related_to".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    /// Validate that this kind is well-formed. `Custom(label)`
    /// must NOT:
    ///
    /// - be empty
    /// - collide with reserved sentinels (`__system__`,
    ///   `__root__`) — these are used as None-tenant sentinels
    ///   in alias / canonical / pair-kind index keys
    /// - collide with a built-in discriminant (`Custom("same_as")`
    ///   would otherwise dedup-collide with `SameAs` in
    ///   `by_pair_kind`)
    ///
    /// Built-in variants always pass.
    ///
    /// **LOAD-BEARING note for future maintainers**:
    /// `IdentityEntityKind::Custom` and `CausalCellKind::Custom`
    /// do NOT yet enforce these rules — a pre-existing gap. P37
    /// does NOT inherit that gap.
    pub fn validate(&self) -> Result<(), String> {
        let Self::Custom(label) = self else {
            return Ok(());
        };
        if label.is_empty() {
            return Err(
                "custom link kind label cannot be empty".to_string()
            );
        }
        if label == "__system__" || label == "__root__" {
            return Err(format!(
                "custom link kind label collides with reserved \
                 sentinel: {label}"
            ));
        }
        // Reject collision with any built-in discriminant. Otherwise
        // `Custom("same_as")` would silently dedup against
        // `SameAs` in the `by_pair_kind` index — caller would
        // expect their custom kind to be a distinct edge type.
        const BUILTIN_DISCRIMINANTS: &[&str] = &[
            "same_as",
            "depends_on",
            "downstream_of",
            "owned_by",
            "produced_by",
            "consumed_by",
            "derived_from",
            "observed_in",
            "part_of",
            "related_to",
        ];
        if BUILTIN_DISCRIMINANTS.contains(&label.as_str()) {
            return Err(format!(
                "custom link kind label '{label}' collides with \
                 built-in discriminant"
            ));
        }
        Ok(())
    }
}

/// A durable directed assertion that two `IdentityEntity` rows
/// have a semantic relationship of a given kind. v0 has no trust
/// verdict over the link; `confidence` is author-asserted and
/// informational only. See the module-level banner for the full
/// suggestion-only contract.
///
/// ## Field semantics
///
/// - `id` — opaque `IdentityLinkId` with prefix `idl_`.
/// - `tenant_id` — strict tenant equality with `from_entity_id`
///   and `to_entity_id` (including `None == None`). Mismatches
///   surface as `"unknown identity entity: {id}"` to prevent
///   cross-tenant existence enumeration.
/// - `kind` — relationship type. Must pass
///   `IdentityLinkKind::validate` at create time.
/// - `from_entity_id` / `to_entity_id` — must reference existing
///   entities in `IdentityStore`. Self-links (`from == to`)
///   rejected at create time, even for `SameAs`.
/// - `confidence` — author-asserted belief in this link.
///   **Informational in v0** — NOT a trust verdict; auto-actions
///   MUST gate on a future `IdentityLinkTrustAssessment`.
/// - `evidence_ids` / `claim_ids` / `cell_ids` — opaque audit
///   references. v0 does NOT validate that the referenced ids
///   exist; they're stored verbatim for the audit trail.
/// - `metadata` — free-form bag. Convention: keys with prefix
///   `_hydra_` are reserved for future engine use (NOT enforced
///   in v0).
/// - `created_by` / `created_at` / `caused_by` — standard audit
///   trail mirroring P29's `IdentityEntity`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityLink {
    pub id: IdentityLinkId,
    pub tenant_id: Option<TenantId>,
    pub kind: IdentityLinkKind,
    pub from_entity_id: IdentityEntityId,
    pub to_entity_id: IdentityEntityId,
    pub confidence: Confidence,
    /// Patch 38 polish — `#[serde(default)]` lets wire callers
    /// omit empty arrays/maps. Common case: a one-shot
    /// `(from)--depends_on-->(to)` link with no audit refs.
    #[serde(default)]
    pub evidence_ids: Vec<EvidenceId>,
    #[serde(default)]
    pub claim_ids: Vec<ClaimId>,
    #[serde(default)]
    pub cell_ids: Vec<CausalCellId>,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub caused_by: Option<EventId>,
}

impl IdentityLink {
    /// Validate that the link is structurally well-formed.
    /// Tenant equality + entity existence are checked at the
    /// `IdentityLinkStore::create_link` boundary because they
    /// require store context.
    ///
    /// Rejects:
    ///
    /// - self-links (`from_entity_id == to_entity_id`), even
    ///   for `SameAs` — a self-`SameAs` is meaningless
    /// - invalid `kind` (empty `Custom`, sentinel `Custom`,
    ///   built-in-collision `Custom`)
    pub fn validate(&self) -> Result<(), String> {
        self.kind.validate()?;
        if self.from_entity_id == self.to_entity_id {
            return Err(format!(
                "self-link rejected: from == to == {}",
                self.from_entity_id
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_entity_kind_serializes_pascal_case() {
        // Wire form: built-in variants serialize as bare
        // PascalCase strings; `Custom(label)` serializes as the
        // externally-tagged dict `{"Custom": "label"}`. Mirrors
        // CausalCellKind exactly. Pinned so a future
        // `#[serde(rename_all)]` change doesn't silently break
        // the wire contract.
        assert_eq!(
            serde_json::to_string(&IdentityEntityKind::Dataset).unwrap(),
            "\"Dataset\""
        );
        assert_eq!(
            serde_json::to_string(&IdentityEntityKind::User).unwrap(),
            "\"User\""
        );
        let custom = IdentityEntityKind::Custom("invoice_table".to_string());
        let json = serde_json::to_string(&custom).unwrap();
        assert_eq!(json, "{\"Custom\":\"invoice_table\"}");
        let parsed: IdentityEntityKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, custom);
    }

    #[test]
    fn identity_entity_kind_discriminant_returns_snake_case() {
        assert_eq!(IdentityEntityKind::Dataset.discriminant(), "dataset");
        assert_eq!(IdentityEntityKind::Table.discriminant(), "table");
        assert_eq!(IdentityEntityKind::Dashboard.discriminant(), "dashboard");
        assert_eq!(IdentityEntityKind::Metric.discriminant(), "metric");
        assert_eq!(IdentityEntityKind::Service.discriminant(), "service");
        assert_eq!(IdentityEntityKind::Agent.discriminant(), "agent");
        assert_eq!(IdentityEntityKind::Workflow.discriminant(), "workflow");
        assert_eq!(IdentityEntityKind::Source.discriminant(), "source");
        assert_eq!(IdentityEntityKind::User.discriminant(), "user");
        assert_eq!(IdentityEntityKind::System.discriminant(), "system");
        assert_eq!(IdentityEntityKind::Incident.discriminant(), "incident");
        assert_eq!(
            IdentityEntityKind::Custom("xyz".to_string()).discriminant(),
            "xyz"
        );
    }

    #[test]
    fn identity_entity_id_uses_ide_prefix() {
        let id = IdentityEntityId::new();
        assert!(
            id.as_str().starts_with("ide_"),
            "expected ide_ prefix, got {}",
            id.as_str()
        );
    }

    #[test]
    fn identity_alias_index_key_is_stable_and_distinct() {
        // Deterministic key format AND distinct tuples must
        // never collide. Pinned because the store's by_alias
        // index keys on this exact string.
        let alias_a = IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some("analytics".to_string()),
            external_id: Some("ANALYTICS.REVENUE_DAILY".to_string()),
            label: "ANALYTICS.REVENUE_DAILY".to_string(),
            normalized: "analytics.revenue_daily".to_string(),
        };
        let tenant_a = TenantId::from_str("tenant_a");
        let key_with_tenant = alias_a.index_key(Some(&tenant_a));
        assert_eq!(
            key_with_tenant,
            "tenant_a|snowflake|analytics|analytics.revenue_daily"
        );

        // Same alias under None tenant uses the sentinel.
        let key_no_tenant = alias_a.index_key(None);
        assert_eq!(
            key_no_tenant,
            "__system__|snowflake|analytics|analytics.revenue_daily"
        );
        assert_ne!(key_with_tenant, key_no_tenant);

        // None namespace renders the namespace sentinel.
        let alias_root = IdentityAlias {
            source: "slack".to_string(),
            namespace: None,
            external_id: None,
            label: "#revenue".to_string(),
            normalized: "#revenue".to_string(),
        };
        let key_root = alias_root.index_key(Some(&tenant_a));
        assert_eq!(key_root, "tenant_a|slack|__root__|#revenue");

        // Stability — same inputs produce same key across calls.
        assert_eq!(alias_a.index_key(Some(&tenant_a)), key_with_tenant);
    }

    #[test]
    fn identity_alias_validate_rejects_sentinel_inputs() {
        // Smuggling `__system__` as a source name would let a
        // caller force a key collision with the legitimate
        // None-tenant slot. Validation rejects it.
        let bad_source = IdentityAlias {
            source: "__system__".to_string(),
            namespace: None,
            external_id: None,
            label: "x".to_string(),
            normalized: "x".to_string(),
        };
        assert!(bad_source.validate().is_err());

        let bad_ns = IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some("__root__".to_string()),
            external_id: None,
            label: "x".to_string(),
            normalized: "x".to_string(),
        };
        assert!(bad_ns.validate().is_err());

        // Empty source / normalized also rejected.
        let empty_source = IdentityAlias {
            source: "".to_string(),
            namespace: None,
            external_id: None,
            label: "x".to_string(),
            normalized: "x".to_string(),
        };
        assert!(empty_source.validate().is_err());

        let empty_norm = IdentityAlias {
            source: "snowflake".to_string(),
            namespace: None,
            external_id: None,
            label: "x".to_string(),
            normalized: "".to_string(),
        };
        assert!(empty_norm.validate().is_err());

        // Well-formed alias passes.
        let good = IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some("analytics".to_string()),
            external_id: None,
            label: "x".to_string(),
            normalized: "analytics.x".to_string(),
        };
        assert!(good.validate().is_ok());
    }

    // === Patch 30 — Semantic Identity Resolution v1 tests ===

    #[test]
    fn match_level_for_score_thresholds_pinned() {
        // Patch 30 — MatchLevel uses the SAME numeric thresholds
        // as TrustLevel (0.80/0.50/0.20) but distinct vocabulary
        // (Strong/Possible/Weak/None). Pin both edges to catch
        // any future drift in the bucketing math.
        assert_eq!(MatchLevel::level_for_score(1.0), MatchLevel::Strong);
        assert_eq!(MatchLevel::level_for_score(0.80), MatchLevel::Strong);
        assert_eq!(
            MatchLevel::level_for_score(0.799),
            MatchLevel::Possible
        );
        assert_eq!(MatchLevel::level_for_score(0.50), MatchLevel::Possible);
        assert_eq!(MatchLevel::level_for_score(0.499), MatchLevel::Weak);
        assert_eq!(MatchLevel::level_for_score(0.20), MatchLevel::Weak);
        assert_eq!(MatchLevel::level_for_score(0.199), MatchLevel::None);
        assert_eq!(MatchLevel::level_for_score(0.0), MatchLevel::None);
    }

    #[test]
    fn match_level_serializes_pascal_case() {
        // Wire form contract for the future P31 SDK/HTTP surface.
        assert_eq!(
            serde_json::to_string(&MatchLevel::Strong).unwrap(),
            "\"Strong\""
        );
        assert_eq!(
            serde_json::to_string(&MatchLevel::Possible).unwrap(),
            "\"Possible\""
        );
        assert_eq!(
            serde_json::to_string(&MatchLevel::Weak).unwrap(),
            "\"Weak\""
        );
        assert_eq!(
            serde_json::to_string(&MatchLevel::None).unwrap(),
            "\"None\""
        );
    }

    #[test]
    fn semantic_identity_match_assessment_serde_roundtrip() {
        // Full envelope round-trips through serde — pinned so the
        // P31 wire surface lands without rewriting fixtures.
        let assessment = SemanticIdentityMatchAssessment {
            query_alias: IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("analytics".to_string()),
                external_id: Some("REVENUE_DAILY".to_string()),
                label: "Revenue Daily".to_string(),
                normalized: "analytics.revenue_daily".to_string(),
            },
            candidates: vec![SemanticIdentityMatchCandidate {
                entity_id: IdentityEntityId::from_str("ide_test"),
                score: 0.92,
                level: MatchLevel::Strong,
                factors: vec![TrustFactor {
                    kind: "exact_alias_match".to_string(),
                    weight: 0.85,
                    applied: true,
                    detail: "alias matches existing entity".to_string(),
                }],
            }],
            assessed_at: chrono::DateTime::parse_from_rfc3339(
                "2026-05-31T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        };
        let json = serde_json::to_string(&assessment).unwrap();
        let restored: SemanticIdentityMatchAssessment =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored, assessment);
    }

    // === Patch 32 — Identity Match Trust tests ===

    fn p32_sample_trust_assessment() -> IdentityMatchTrustAssessment {
        IdentityMatchTrustAssessment {
            query_alias: IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("analytics".to_string()),
                external_id: Some("REVENUE_DAILY".to_string()),
                label: "Revenue Daily".to_string(),
                normalized: "analytics.revenue_daily".to_string(),
            },
            candidate_entity_id: IdentityEntityId::from_str(
                "ide_revenue_daily",
            ),
            match_score: 0.95,
            match_level: MatchLevel::Strong,
            score: 0.90,
            level: crate::trust::TrustLevel::High,
            explanation: "Strong semantic match with high entity \
                          confidence and no alias conflict."
                .to_string(),
            factors: vec![
                TrustFactor {
                    kind: "exact_alias_match".to_string(),
                    weight: 0.40,
                    applied: true,
                    detail: "alias appears verbatim on candidate"
                        .to_string(),
                },
                TrustFactor {
                    kind: "semantic_match_strong".to_string(),
                    weight: 0.25,
                    applied: true,
                    detail: "P30 score 0.95 (≥ 0.80)".to_string(),
                },
            ],
            assessed_at: chrono::DateTime::parse_from_rfc3339(
                "2026-05-31T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        }
    }

    #[test]
    fn identity_match_trust_assessment_serde_round_trip() {
        // Full envelope must round-trip through serde. Pinned
        // so the future P33 SDK lands without rewriting
        // fixtures. PascalCase wire form for both `match_level`
        // (MatchLevel) and `level` (TrustLevel) preserved.
        let assessment = p32_sample_trust_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        // Both PascalCase strings on the wire.
        assert!(json.contains("\"match_level\":\"Strong\""));
        assert!(json.contains("\"level\":\"High\""));
        let restored: IdentityMatchTrustAssessment =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored, assessment);
    }

    #[test]
    fn identity_match_trust_assessment_carries_match_level_passthrough() {
        // `match_level` is the P30 axis ("how strongly do these
        // names resemble each other?") while `level` is the
        // P32 axis ("do I trust this match?"). They live
        // side-by-side on the envelope and are independently
        // typed. Pinned because conflating them is the most
        // likely silent regression downstream.
        let mut assessment = p32_sample_trust_assessment();
        // Strong match (P30) but Low trust (P32). e.g., alias
        // conflict dragged the trust score down.
        assessment.match_level = MatchLevel::Strong;
        assessment.match_score = 0.90;
        assessment.level = crate::trust::TrustLevel::Low;
        assessment.score = 0.25;
        let json = serde_json::to_string(&assessment).unwrap();
        let restored: IdentityMatchTrustAssessment =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored.match_level, MatchLevel::Strong);
        assert_eq!(restored.level, crate::trust::TrustLevel::Low);
        // Distinct fields — not the same value via type
        // confusion.
        assert!(
            (restored.match_score - 0.90).abs() < 1e-9
                && (restored.score - 0.25).abs() < 1e-9
        );
    }

    #[test]
    fn identity_match_trust_assessment_level_matches_trust_thresholds() {
        // P32's `level` is computed via
        // `TrustAssessment::level_for_score`. Pin that the
        // type is the `TrustLevel` shared with claim/cell
        // trust, not a P32-specific reinvention. Bucketing
        // edges are tested at the trust.rs level — here we
        // just confirm we can stamp each variant.
        for (score, expected) in [
            (1.0_f64, crate::trust::TrustLevel::High),
            (0.80, crate::trust::TrustLevel::High),
            (0.50, crate::trust::TrustLevel::Medium),
            (0.20, crate::trust::TrustLevel::Low),
            (0.0, crate::trust::TrustLevel::Unknown),
        ] {
            let mut a = p32_sample_trust_assessment();
            a.score = score;
            a.level = crate::trust::TrustAssessment::level_for_score(score);
            assert_eq!(a.level, expected, "score = {score}");
        }
    }

    // === Patch 33 — Identity Entity Trust tests ===

    fn p33_sample_entity_trust_assessment() -> IdentityEntityTrustAssessment {
        IdentityEntityTrustAssessment {
            entity_id: IdentityEntityId::from_str("ide_revenue_daily"),
            score: 0.85,
            level: crate::trust::TrustLevel::High,
            explanation: "Well-formed identity record with multi-source \
                          aliases and no conflicts."
                .to_string(),
            factors: vec![
                TrustFactor {
                    kind: "entity_confidence_high".to_string(),
                    weight: 0.30,
                    applied: true,
                    detail: "confidence 0.95 (≥ 0.80)".to_string(),
                },
                TrustFactor {
                    kind: "multiple_aliases".to_string(),
                    weight: 0.10,
                    applied: true,
                    detail: "3 aliases".to_string(),
                },
            ],
            assessed_at: chrono::DateTime::parse_from_rfc3339(
                "2026-05-31T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        }
    }

    #[test]
    fn identity_entity_trust_assessment_serde_round_trip() {
        // Full envelope must round-trip through serde. Pinned
        // so the future P34 wire surface lands without
        // rewriting fixtures. PascalCase `level` (TrustLevel)
        // pinned.
        let assessment = p33_sample_entity_trust_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        assert!(json.contains("\"level\":\"High\""));
        let restored: IdentityEntityTrustAssessment =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored, assessment);
    }

    #[test]
    fn identity_entity_trust_assessment_omits_related_ids_in_v1() {
        // Adaptation B pin: v1 type must NOT carry
        // `related_claim_ids` or `related_cell_ids` fields.
        // Carrying empty vecs would mis-signal what the
        // assessment computed. Type stays honest now;
        // additive fields land in P35+ when the relevant
        // factors fire. If a future patch adds them, this
        // test will need updating intentionally (a tripwire
        // against accidental scope creep).
        //
        // We verify by attempting to deserialize a JSON
        // payload that DOES include those fields with
        // `extra="forbid"`-style strictness: the type uses
        // serde's default behavior (extra fields ignored on
        // deserialize for normal structs, but the SERIALIZE
        // side does NOT include them — which is what the v1
        // wire contract requires).
        let assessment = p33_sample_entity_trust_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        assert!(
            !json.contains("related_claim_ids"),
            "v1 wire shape must not carry related_claim_ids; \
             got {json}"
        );
        assert!(
            !json.contains("related_cell_ids"),
            "v1 wire shape must not carry related_cell_ids"
        );
    }

    #[test]
    fn identity_entity_trust_assessment_level_matches_trust_thresholds() {
        // Pin that `level` is the `TrustLevel` shared with
        // claim/cell trust, not a P33-specific reinvention.
        // Bucketing edges are tested at trust.rs level — here
        // we just confirm each variant can be stamped.
        for (score, expected) in [
            (0.85_f64, crate::trust::TrustLevel::High), // v1 ceiling
            (0.80, crate::trust::TrustLevel::High),
            (0.50, crate::trust::TrustLevel::Medium),
            (0.20, crate::trust::TrustLevel::Low),
            (0.0, crate::trust::TrustLevel::Unknown),
        ] {
            let mut a = p33_sample_entity_trust_assessment();
            a.score = score;
            a.level = crate::trust::TrustAssessment::level_for_score(score);
            assert_eq!(a.level, expected, "score = {score}");
        }
    }

    // === Patch 35 — Source Trust v1 tests ===

    fn p35_sample_source_trust_assessment() -> SourceTrustAssessment {
        SourceTrustAssessment {
            source: "snowflake".to_string(),
            score: 0.80,
            level: crate::trust::TrustLevel::High,
            explanation: "Source verdict High (score 0.80) — 5 entities across \
                          3 kinds, mean entity trust 0.78, 2 reliable evidence \
                          records."
                .to_string(),
            factors: vec![
                TrustFactor {
                    kind: "source_has_identity_aliases".to_string(),
                    weight: 0.20,
                    applied: true,
                    detail: "5 entities reference this source".to_string(),
                },
                TrustFactor {
                    kind: "low_trust_entities_from_source".to_string(),
                    weight: -0.20,
                    applied: false,
                    detail: "mean entity trust 0.78 (> 0.40)".to_string(),
                },
            ],
            related_entity_ids: vec![
                IdentityEntityId::from_str("ide_dash0"),
                IdentityEntityId::from_str("ide_d0"),
                IdentityEntityId::from_str("ide_d1"),
                IdentityEntityId::from_str("ide_d2"),
                IdentityEntityId::from_str("ide_t0"),
            ],
            entity_sample_size: 5,
            evidence_sample_size: 2,
            assessed_at: chrono::DateTime::parse_from_rfc3339(
                "2026-06-01T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        }
    }

    #[test]
    fn source_trust_assessment_serde_round_trip() {
        // Full envelope must round-trip through serde. PascalCase
        // `level` (TrustLevel) pinned. Sample sizes round-trip as
        // bare u64-shaped fields. Pinned so the future P36 wire
        // surface lands without rewriting fixtures.
        let assessment = p35_sample_source_trust_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        assert!(json.contains("\"level\":\"High\""));
        assert!(json.contains("\"entity_sample_size\":5"));
        assert!(json.contains("\"evidence_sample_size\":2"));
        let restored: SourceTrustAssessment =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored, assessment);
    }

    #[test]
    fn source_trust_assessment_pascal_case_wire_form() {
        // The wire-facing JSON must carry the same camelCase /
        // PascalCase shape established by P32 / P33. Pin the field
        // names so a future `#[serde(rename_all)]` change doesn't
        // silently break HTTP contracts.
        let assessment = p35_sample_source_trust_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        // Field names are snake_case Rust idents — pinned exactly.
        assert!(json.contains("\"source\":\"snowflake\""));
        assert!(json.contains("\"score\":"));
        assert!(json.contains("\"level\":\"High\""));
        assert!(json.contains("\"explanation\":"));
        assert!(json.contains("\"factors\":"));
        // Patch 36 Adaptation A1 — related_entity_ids on the wire.
        assert!(json.contains("\"related_entity_ids\":"));
        assert!(json.contains("\"entity_sample_size\":"));
        assert!(json.contains("\"evidence_sample_size\":"));
        assert!(json.contains("\"assessed_at\":"));
    }

    #[test]
    fn source_trust_assessment_level_uses_existing_thresholds() {
        // Pin that `level` is the SHARED `TrustLevel` (≥0.80 High,
        // ≥0.50 Medium, ≥0.20 Low, else Unknown). Bucketing edges
        // are tested at trust.rs level — here we just confirm
        // each variant can be stamped via the shared bucketing
        // helper. Wrinkle E pin: empty-source-result buckets via
        // level_for_score(0.0) → Unknown, NOT via a new
        // TrustLevel::Unknown variant on a P35-specific enum.
        for (score, expected) in [
            (0.80_f64, crate::trust::TrustLevel::High), // v1 ceiling exactly
            (0.50, crate::trust::TrustLevel::Medium),
            (0.20, crate::trust::TrustLevel::Low),
            (0.00, crate::trust::TrustLevel::Unknown),
        ] {
            let mut a = p35_sample_source_trust_assessment();
            a.score = score;
            a.level = crate::trust::TrustAssessment::level_for_score(score);
            assert_eq!(a.level, expected, "score = {score}");
        }
    }

    // === Patch 37 — IdentityLink vocabulary tests ===

    #[test]
    fn identity_link_id_uses_idl_prefix() {
        let id = IdentityLinkId::new();
        assert!(
            id.as_str().starts_with("idl_"),
            "expected idl_ prefix, got {}",
            id.as_str()
        );
    }

    #[test]
    fn identity_link_kind_serializes_pascal_case() {
        // Wire form: built-in variants serialize as bare
        // PascalCase strings; `Custom(label)` serializes as the
        // externally-tagged dict `{"Custom": "label"}`. Mirrors
        // IdentityEntityKind exactly. Pinned so a future
        // `#[serde(rename_all)]` change doesn't silently break
        // the wire contract.
        assert_eq!(
            serde_json::to_string(&IdentityLinkKind::SameAs).unwrap(),
            "\"SameAs\""
        );
        assert_eq!(
            serde_json::to_string(&IdentityLinkKind::DependsOn).unwrap(),
            "\"DependsOn\""
        );
        assert_eq!(
            serde_json::to_string(&IdentityLinkKind::PartOf).unwrap(),
            "\"PartOf\""
        );
        let custom = IdentityLinkKind::Custom("uses_metric".to_string());
        let json = serde_json::to_string(&custom).unwrap();
        assert_eq!(json, "{\"Custom\":\"uses_metric\"}");
        let parsed: IdentityLinkKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, custom);
    }

    #[test]
    fn identity_link_kind_discriminant_returns_snake_case() {
        // All 10 built-ins return snake_case; Custom returns its
        // label verbatim (used by IdentityLinkStore's by_kind +
        // by_pair_kind indexes).
        assert_eq!(IdentityLinkKind::SameAs.discriminant(), "same_as");
        assert_eq!(IdentityLinkKind::DependsOn.discriminant(), "depends_on");
        assert_eq!(
            IdentityLinkKind::DownstreamOf.discriminant(),
            "downstream_of"
        );
        assert_eq!(IdentityLinkKind::OwnedBy.discriminant(), "owned_by");
        assert_eq!(
            IdentityLinkKind::ProducedBy.discriminant(),
            "produced_by"
        );
        assert_eq!(
            IdentityLinkKind::ConsumedBy.discriminant(),
            "consumed_by"
        );
        assert_eq!(
            IdentityLinkKind::DerivedFrom.discriminant(),
            "derived_from"
        );
        assert_eq!(
            IdentityLinkKind::ObservedIn.discriminant(),
            "observed_in"
        );
        assert_eq!(IdentityLinkKind::PartOf.discriminant(), "part_of");
        assert_eq!(IdentityLinkKind::RelatedTo.discriminant(), "related_to");
        assert_eq!(
            IdentityLinkKind::Custom("uses_metric".to_string()).discriminant(),
            "uses_metric"
        );
    }

    #[test]
    fn identity_link_kind_custom_rejects_sentinel_label() {
        // LOAD-BEARING — IdentityEntityKind::Custom and
        // CausalCellKind::Custom do NOT validate against
        // sentinels today; P37 must NOT inherit that gap.
        assert!(
            IdentityLinkKind::Custom("".to_string()).validate().is_err(),
            "empty Custom label must be rejected"
        );
        assert!(
            IdentityLinkKind::Custom("__system__".to_string())
                .validate()
                .is_err(),
            "sentinel __system__ must be rejected"
        );
        assert!(
            IdentityLinkKind::Custom("__root__".to_string())
                .validate()
                .is_err(),
            "sentinel __root__ must be rejected"
        );
        // Built-ins always pass validate.
        assert!(IdentityLinkKind::SameAs.validate().is_ok());
        assert!(IdentityLinkKind::DependsOn.validate().is_ok());
        // Well-formed Custom passes.
        assert!(
            IdentityLinkKind::Custom("uses_metric".to_string())
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn identity_link_kind_custom_rejects_builtin_collision() {
        // LOAD-BEARING — Custom("same_as") would dedup-collide
        // with SameAs in IdentityLinkStore's by_pair_kind index.
        // Reject all 10 built-in discriminants explicitly.
        for collision in [
            "same_as",
            "depends_on",
            "downstream_of",
            "owned_by",
            "produced_by",
            "consumed_by",
            "derived_from",
            "observed_in",
            "part_of",
            "related_to",
        ] {
            let result =
                IdentityLinkKind::Custom(collision.to_string()).validate();
            assert!(
                result.is_err(),
                "Custom('{collision}') must be rejected as built-in \
                 discriminant collision; got {result:?}"
            );
        }
    }

    #[test]
    fn identity_link_validate_rejects_self_link() {
        // Self-links (from == to) are meaningless even for
        // SameAs — rejected at the type level.
        let entity_id = IdentityEntityId::from_str("ide_alone");
        let link = IdentityLink {
            id: IdentityLinkId::new(),
            tenant_id: None,
            kind: IdentityLinkKind::SameAs,
            from_entity_id: entity_id.clone(),
            to_entity_id: entity_id,
            confidence: crate::epistemic::Confidence::new(0.9),
            evidence_ids: vec![],
            claim_ids: vec![],
            cell_ids: vec![],
            metadata: HashMap::new(),
            created_by: crate::id::ActorId::from_str("actor_ops"),
            created_at: Utc::now(),
            caused_by: None,
        };
        let err = link.validate().unwrap_err();
        assert!(
            err.contains("self-link rejected"),
            "expected self-link rejection, got: {err}"
        );
    }

    #[test]
    fn identity_link_serde_default_polish_accepts_minimal_body() {
        // Patch 38 polish — wire callers can omit empty arrays /
        // maps / caused_by. With `#[serde(default)]` on
        // evidence_ids, claim_ids, cell_ids, metadata, caused_by,
        // a minimal POST body deserializes cleanly. Pinned so a
        // future patch can't accidentally drop the defaults.
        let minimal = serde_json::json!({
            "id": "idl_min",
            "tenant_id": "tenant_x",
            "kind": "DependsOn",
            "from_entity_id": "ide_a",
            "to_entity_id": "ide_b",
            "confidence": 0.9,
            "created_by": "actor_ops",
            "created_at": "2026-06-01T12:00:00Z"
            // evidence_ids / claim_ids / cell_ids / metadata /
            // caused_by absent — must default cleanly.
        });
        let link: IdentityLink = serde_json::from_value(minimal).unwrap();
        assert!(link.evidence_ids.is_empty());
        assert!(link.claim_ids.is_empty());
        assert!(link.cell_ids.is_empty());
        assert!(link.metadata.is_empty());
        assert!(link.caused_by.is_none());
        assert_eq!(link.kind, IdentityLinkKind::DependsOn);
    }

    #[test]
    fn identity_link_serde_round_trip() {
        // Full envelope must round-trip through serde. Wire
        // contract pin for P38 wire surface.
        let link = IdentityLink {
            id: IdentityLinkId::from_str("idl_xyz"),
            tenant_id: Some(crate::id::TenantId::from_str("tenant_test")),
            kind: IdentityLinkKind::DependsOn,
            from_entity_id: IdentityEntityId::from_str("ide_a"),
            to_entity_id: IdentityEntityId::from_str("ide_b"),
            confidence: crate::epistemic::Confidence::new(0.85),
            evidence_ids: vec![crate::id::EvidenceId::from_str("evd_1")],
            claim_ids: vec![crate::id::ClaimId::from_str("claim_1")],
            cell_ids: vec![crate::id::CausalCellId::from_str("cell_1")],
            metadata: {
                let mut m = HashMap::new();
                m.insert(
                    "source".to_string(),
                    crate::event::Value::String("dbt_manifest".to_string()),
                );
                m
            },
            created_by: crate::id::ActorId::from_str("actor_ops"),
            created_at: chrono::DateTime::parse_from_rfc3339(
                "2026-06-01T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
            caused_by: None,
        };
        let json = serde_json::to_string(&link).unwrap();
        assert!(json.contains("\"kind\":\"DependsOn\""));
        let restored: IdentityLink = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, link);
    }
}
