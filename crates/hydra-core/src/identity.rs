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
use crate::id::{ActorId, EventId, IdentityEntityId, TenantId};
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
}
