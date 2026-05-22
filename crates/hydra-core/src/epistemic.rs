use crate::event::Value;
use crate::id::{ActorId, EdgeId, EventId, EvidenceId, NodeId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Confidence is a normalized score in [0.0, 1.0].
/// It is not a probability guarantee; it is Hydra's current belief strength.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(pub f64);

impl Confidence {
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self(1.0)
    }
}

/// Where a piece of evidence came from.
/// Evidence is the raw/provenance-bearing material Hydra uses to support or
/// challenge claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceSource {
    Warehouse {
        system: String,
        database: Option<String>,
        schema: Option<String>,
        table: Option<String>,
    },
    Api {
        system: String,
        endpoint: Option<String>,
    },
    Document {
        uri: String,
    },
    Human {
        actor_id: ActorId,
    },
    Agent {
        actor_id: ActorId,
    },
    System {
        name: String,
    },
}

/// Flexible but typed evidence payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePayload {
    pub kind: String,
    pub data: HashMap<String, Value>,
}

/// A provenance-bearing observation that can support or contradict claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub tenant_id: Option<TenantId>,
    pub source: EvidenceSource,
    pub payload: EvidencePayload,
    pub reliability: Confidence,
    pub observed_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub caused_by: Option<EventId>,
}

/// What kind of belief Hydra is storing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimKind {
    Fact,
    Inference,
    Hypothesis,
    Prediction,
    Recommendation,
    PolicyFinding,
    AnomalyFinding,
    LineageFinding,
}

/// The subject a claim is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimSubject {
    Node(NodeId),
    Edge(EdgeId),
    ExternalRef(String),
    Dataset(String),
    Metric(String),
    System(String),
}

/// The object/value asserted by a claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimObject {
    Node(NodeId),
    Edge(EdgeId),
    Value(Value),
    ExternalRef(String),
}

/// Claim lifecycle. Truth is not boolean in Hydra; it moves through states.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimStatus {
    Proposed,
    Supported,
    Verified,
    Operational,
    Disputed,
    Stale,
    Retracted,
    Archived,
}

/// A statement Hydra currently believes, doubts, verifies, or operationalizes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub id: crate::id::ClaimId,
    pub tenant_id: Option<TenantId>,
    pub kind: ClaimKind,
    pub subject: ClaimSubject,
    pub predicate: String,
    pub object: ClaimObject,
    pub confidence: Confidence,
    pub status: ClaimStatus,
    pub evidence_for: Vec<EvidenceId>,
    pub evidence_against: Vec<EvidenceId>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub caused_by: Option<EventId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{ActorId, ClaimId, EvidenceId};

    #[test]
    fn confidence_is_clamped() {
        assert_eq!(Confidence::new(-1.0).value(), 0.0);
        assert_eq!(Confidence::new(2.0).value(), 1.0);
        assert_eq!(Confidence::new(0.42).value(), 0.42);
    }

    #[test]
    fn claim_serde_roundtrip() {
        let now = Utc::now();
        let claim = Claim {
            id: ClaimId::new(),
            tenant_id: None,
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.91),
            status: ClaimStatus::Proposed,
            evidence_for: vec![EvidenceId::new()],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: ActorId::from_str("actor_argus"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };

        let json = serde_json::to_string(&claim).unwrap();
        let restored: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, restored);
    }
}
