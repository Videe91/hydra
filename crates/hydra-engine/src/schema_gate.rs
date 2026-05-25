use crate::schema_registry_store::SchemaRegistryStore;
use crate::schema_validator::{
    SchemaValidationError, SchemaValidationReport, SchemaValidator,
};
use hydra_core::error::Result;
use hydra_core::{EventKind, Value};
use std::collections::HashMap;

/// Closure type used to resolve a NodeId to its current TypeId during
/// NodeUpdated validation. SchemaGate is projection-agnostic; callers
/// (typically Hydra::ingest_event_internal) supply this to bridge in.
pub type NodeTypeResolver<'a> = dyn Fn(&hydra_core::NodeId) -> Option<hydra_core::TypeId> + 'a;

/// Closure type used to resolve an EdgeId to its current TypeId
/// during EdgeUpdated validation. Same shape as
/// [`NodeTypeResolver`]; the gate cannot read the projection on
/// its own.
pub type EdgeTypeResolver<'a> = dyn Fn(&hydra_core::EdgeId) -> Option<hydra_core::TypeId> + 'a;

/// How aggressively Hydra should enforce schema validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaGateMode {
    /// Do not validate or block.
    Off,
    /// Validate and reject invalid events before cascade/commit.
    Strict,
    /// Validate, allow original event, and optionally emit diagnostics later.
    ///
    /// v0 does not emit diagnostics here yet. That can be added via a future
    /// SchemaAgent. For now, Permissive behaves like "validate but do not block".
    Permissive,
}

/// What to do when an event has no registered schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSchemaPolicy {
    Allow,
    Reject,
}

/// Schema gate configuration.
///
/// Default is deliberately non-breaking:
/// - mode = Off
/// - unknown schemas are allowed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaGateConfig {
    pub mode: SchemaGateMode,
    pub unknown_schema_policy: UnknownSchemaPolicy,
}

impl Default for SchemaGateConfig {
    fn default() -> Self {
        Self {
            mode: SchemaGateMode::Off,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        }
    }
}

/// Pre-cascade schema validation gate.
///
/// This gate does not mutate state and does not emit events.
/// In Strict mode, invalid writes are rejected before:
/// - cascade
/// - projection mutation
/// - commit ledger
/// - commit writer
/// - WAL
#[derive(Debug, Clone, Default)]
pub struct SchemaGate {
    config: SchemaGateConfig,
}

impl SchemaGate {
    pub fn new(config: SchemaGateConfig) -> Self {
        Self { config }
    }

    pub fn disabled() -> Self {
        Self::new(SchemaGateConfig {
            mode: SchemaGateMode::Off,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        })
    }

    pub fn strict_allow_unknown() -> Self {
        Self::new(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        })
    }

    pub fn strict_reject_unknown() -> Self {
        Self::new(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Reject,
        })
    }

    pub fn config(&self) -> &SchemaGateConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: SchemaGateConfig) {
        self.config = config;
    }

    pub fn is_enabled(&self) -> bool {
        self.config.mode != SchemaGateMode::Off
    }

    /// Validate one incoming event before it enters the cascade. No node
    /// resolver — NodeUpdated is treated as valid because the gate cannot
    /// look up the node's TypeId on its own.
    pub fn validate_event(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        event: &hydra_core::Event,
    ) -> Result<()> {
        self.validate_event_kind(store, validator, &event.kind)
    }

    /// Validate one incoming event with a projection-backed node type
    /// resolver. Required for NodeUpdated, which only carries node_id +
    /// changes — the gate needs the resolver to recover the TypeId.
    pub fn validate_event_with_node_resolver(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        event: &hydra_core::Event,
        node_type_resolver: Option<&NodeTypeResolver<'_>>,
    ) -> Result<()> {
        self.validate_event_kind_with_resolvers(
            store,
            validator,
            &event.kind,
            node_type_resolver,
            None,
        )
    }

    /// Validate one incoming event with both node and edge type
    /// resolvers — the full-coverage entrypoint. NodeUpdated and
    /// EdgeUpdated both need engine-side lookups to recover the
    /// TypeId from the id alone.
    pub fn validate_event_with_resolvers(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        event: &hydra_core::Event,
        node_type_resolver: Option<&NodeTypeResolver<'_>>,
        edge_type_resolver: Option<&EdgeTypeResolver<'_>>,
    ) -> Result<()> {
        self.validate_event_kind_with_resolvers(
            store,
            validator,
            &event.kind,
            node_type_resolver,
            edge_type_resolver,
        )
    }

    /// Validate one incoming EventKind before it enters the cascade. No
    /// resolvers supplied — NodeUpdated / EdgeUpdated pass through. For
    /// full coverage, use [`Self::validate_event_kind_with_resolvers`].
    pub fn validate_event_kind(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        kind: &EventKind,
    ) -> Result<()> {
        self.validate_event_kind_with_resolvers(store, validator, kind, None, None)
    }

    /// Backwards-compatible single-resolver entrypoint. Delegates to
    /// [`Self::validate_event_kind_with_resolvers`] with no edge
    /// resolver.
    pub fn validate_event_kind_with_node_resolver(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        kind: &EventKind,
        node_type_resolver: Option<&NodeTypeResolver<'_>>,
    ) -> Result<()> {
        self.validate_event_kind_with_resolvers(
            store,
            validator,
            kind,
            node_type_resolver,
            None,
        )
    }

    /// Validate one incoming EventKind before it enters the cascade,
    /// with optional resolvers for NodeUpdated (NodeId → TypeId) and
    /// EdgeUpdated (EdgeId → TypeId).
    pub fn validate_event_kind_with_resolvers(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        kind: &EventKind,
        node_type_resolver: Option<&NodeTypeResolver<'_>>,
        edge_type_resolver: Option<&EdgeTypeResolver<'_>>,
    ) -> Result<()> {
        if self.config.mode == SchemaGateMode::Off {
            return Ok(());
        }
        let report = match kind {
            EventKind::EvidenceAdded { evidence } => {
                let report = validator.validate_evidence(store, evidence);
                if report.schema_id.is_none()
                    && self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject
                {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            evidence_kind_path(evidence),
                            "no registered evidence payload schema",
                        )],
                    )
                } else {
                    report
                }
            }
            EventKind::ClaimProposed { claim } => {
                let report = validator.validate_claim(store, claim);
                if report.schema_id.is_none()
                    && self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject
                {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            claim_predicate_path(claim),
                            "no registered claim predicate schema",
                        )],
                    )
                } else {
                    report
                }
            }
            EventKind::ActionProposed { action } => {
                let report = validator.validate_action_payload(store, action);
                if report.schema_id.is_none()
                    && self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject
                {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            action_kind_path(&action.kind),
                            "no registered action payload schema",
                        )],
                    )
                } else {
                    report
                }
            }
            EventKind::PolicyRegistered { policy } => {
                let report = validator.validate_policy_condition(store, policy);
                if report.schema_id.is_none()
                    && self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject
                {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            policy_kind_path(&policy.kind),
                            "no registered policy condition schema",
                        )],
                    )
                } else {
                    report
                }
            }
            EventKind::NodeCreated {
                type_id, properties, ..
            } => {
                let type_id = hydra_core::TypeId::from_str(type_id);
                let report = validator.validate_node_create(store, &type_id, properties);
                if report.schema_id.is_none()
                    && self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject
                {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("node.{}", type_id),
                            "no registered entity type schema",
                        )],
                    )
                } else {
                    report
                }
            }
            EventKind::NodeUpdated { node_id, changes } => self.evaluate_node_update(
                store,
                validator,
                node_id,
                changes,
                node_type_resolver,
            ),
            EventKind::EdgeCreated {
                type_id, properties, ..
            } => {
                let type_id = hydra_core::TypeId::from_str(type_id);
                let report = validator.validate_edge_create(store, &type_id, properties);
                if report.schema_id.is_none()
                    && self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject
                {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("edge.{}", type_id),
                            "no registered edge type schema",
                        )],
                    )
                } else {
                    report
                }
            }
            EventKind::EdgeUpdated { edge_id, changes } => self.evaluate_edge_update(
                store,
                validator,
                edge_id,
                changes,
                edge_type_resolver,
            ),
            _ => SchemaValidationReport::valid(None),
        };
        match self.config.mode {
            SchemaGateMode::Off => Ok(()),
            SchemaGateMode::Permissive => {
                // Future patch: SchemaAgent can emit diagnostic Signals here.
                Ok(())
            }
            SchemaGateMode::Strict => report.into_result(),
        }
    }

    /// Resolve TypeId for NodeUpdated and validate the changes. Factored
    /// out to avoid nested let-else chains in the main match.
    fn evaluate_node_update(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        node_id: &hydra_core::NodeId,
        changes: &HashMap<String, Value>,
        node_type_resolver: Option<&NodeTypeResolver<'_>>,
    ) -> SchemaValidationReport {
        let reject_unknown = self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject;
        let resolver = match node_type_resolver {
            Some(resolver) => resolver,
            None => {
                return if reject_unknown {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("node.{}", node_id),
                            "node update gating requires a node type resolver",
                        )],
                    )
                } else {
                    SchemaValidationReport::valid(None)
                };
            }
        };
        let type_id = match resolver(node_id) {
            Some(type_id) => type_id,
            None => {
                return if reject_unknown {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("node.{}", node_id),
                            "cannot resolve node type for update",
                        )],
                    )
                } else {
                    SchemaValidationReport::valid(None)
                };
            }
        };
        let schema = match store.entity_schema(&type_id) {
            Some(schema) => schema,
            None => {
                return if reject_unknown {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("node.{}", type_id),
                            "no registered entity type schema",
                        )],
                    )
                } else {
                    SchemaValidationReport::valid(None)
                };
            }
        };
        validator.validate_node_update(schema, changes)
    }

    /// Resolve TypeId for EdgeUpdated and validate the changes —
    /// parallel to [`Self::evaluate_node_update`].
    fn evaluate_edge_update(
        &self,
        store: &SchemaRegistryStore,
        validator: &SchemaValidator,
        edge_id: &hydra_core::EdgeId,
        changes: &HashMap<String, Value>,
        edge_type_resolver: Option<&EdgeTypeResolver<'_>>,
    ) -> SchemaValidationReport {
        let reject_unknown = self.config.unknown_schema_policy == UnknownSchemaPolicy::Reject;
        let resolver = match edge_type_resolver {
            Some(resolver) => resolver,
            None => {
                return if reject_unknown {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("edge.{}", edge_id),
                            "edge update gating requires an edge type resolver",
                        )],
                    )
                } else {
                    SchemaValidationReport::valid(None)
                };
            }
        };
        let type_id = match resolver(edge_id) {
            Some(type_id) => type_id,
            None => {
                return if reject_unknown {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("edge.{}", edge_id),
                            "cannot resolve edge type for update",
                        )],
                    )
                } else {
                    SchemaValidationReport::valid(None)
                };
            }
        };
        let schema = match store.edge_schema(&type_id) {
            Some(schema) => schema,
            None => {
                return if reject_unknown {
                    SchemaValidationReport::invalid(
                        None,
                        vec![SchemaValidationError::new(
                            None,
                            format!("edge.{}", type_id),
                            "no registered edge type schema",
                        )],
                    )
                } else {
                    SchemaValidationReport::valid(None)
                };
            }
        };
        validator.validate_edge_update(schema, changes)
    }

    /// Build a diagnostic Signal for permissive-mode future wiring.
    ///
    /// This is intentionally public so a later SchemaAgent can reuse it.
    pub fn diagnostic_signal(report: &SchemaValidationReport) -> Option<EventKind> {
        if report.is_valid() {
            return None;
        }
        let mut payload = HashMap::new();
        if let Some(schema_id) = &report.schema_id {
            payload.insert(
                "schema_id".to_string(),
                Value::String(schema_id.to_string()),
            );
        }
        payload.insert(
            "errors".to_string(),
            Value::List(
                report
                    .errors
                    .iter()
                    .map(|error| {
                        let mut map = HashMap::new();
                        if let Some(schema_id) = &error.schema_id {
                            map.insert(
                                "schema_id".to_string(),
                                Value::String(schema_id.to_string()),
                            );
                        }
                        map.insert("path".to_string(), Value::String(error.path.clone()));
                        map.insert("message".to_string(), Value::String(error.message.clone()));
                        Value::Map(map)
                    })
                    .collect(),
            ),
        );
        Some(EventKind::Signal {
            source: hydra_core::NodeId::from_str("hydra.schema_gate"),
            name: "schema.validation_failed".to_string(),
            payload,
        })
    }
}

fn action_kind_path(kind: &hydra_core::ActionKind) -> String {
    format!("action.{}", action_kind_key(kind))
}

fn policy_kind_path(kind: &hydra_core::PolicyKind) -> String {
    format!("policy.{}", policy_kind_key(kind))
}

fn evidence_kind_path(evidence: &hydra_core::Evidence) -> String {
    format!("evidence.{}", evidence.payload.kind)
}

fn claim_predicate_path(claim: &hydra_core::Claim) -> String {
    format!("claim.{}", claim.predicate)
}

fn action_kind_key(kind: &hydra_core::ActionKind) -> String {
    match kind {
        hydra_core::ActionKind::Notify => "Notify".to_string(),
        hydra_core::ActionKind::CreateTicket => "CreateTicket".to_string(),
        hydra_core::ActionKind::AssignOwner => "AssignOwner".to_string(),
        hydra_core::ActionKind::RequestEvidence => "RequestEvidence".to_string(),
        hydra_core::ActionKind::Quarantine => "Quarantine".to_string(),
        hydra_core::ActionKind::Backfill => "Backfill".to_string(),
        hydra_core::ActionKind::Repair => "Repair".to_string(),
        hydra_core::ActionKind::Approve => "Approve".to_string(),
        hydra_core::ActionKind::Reject => "Reject".to_string(),
        hydra_core::ActionKind::ExecuteWorkflow => "ExecuteWorkflow".to_string(),
        hydra_core::ActionKind::PostLedgerEntry => "PostLedgerEntry".to_string(),
        hydra_core::ActionKind::RunPayroll => "RunPayroll".to_string(),
        hydra_core::ActionKind::Custom(value) => format!("Custom:{value}"),
    }
}

fn policy_kind_key(kind: &hydra_core::PolicyKind) -> String {
    match kind {
        hydra_core::PolicyKind::AutoApproval => "AutoApproval".to_string(),
        hydra_core::PolicyKind::HumanApproval => "HumanApproval".to_string(),
        hydra_core::PolicyKind::Block => "Block".to_string(),
        hydra_core::PolicyKind::Escalation => "Escalation".to_string(),
        hydra_core::PolicyKind::ReviewRequirement => "ReviewRequirement".to_string(),
        hydra_core::PolicyKind::Compliance => "Compliance".to_string(),
        hydra_core::PolicyKind::Security => "Security".to_string(),
        hydra_core::PolicyKind::Finance => "Finance".to_string(),
        hydra_core::PolicyKind::Payroll => "Payroll".to_string(),
        hydra_core::PolicyKind::Custom(value) => format!("Custom:{value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_registry_store::SchemaRegistryStore;
    use crate::schema_validator::SchemaValidator;
    use hydra_core::{
        Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
        Claim, ClaimId, ClaimKind, ClaimObject, ClaimPredicateSchema, ClaimStatus, ClaimSubject,
        Confidence, EntityTypeSchema, Event, EventId, EventKind, Evidence, EvidenceId,
        EvidencePayload, EvidencePayloadSchema, EvidenceSource, FieldSchema, NodeId, Policy,
        PolicyConditionSchema, PolicyId, PolicyKind, PolicyScope, PolicyStatus, SchemaDefinition,
        SchemaId, SchemaStatus, TypeId, Value, ValueType,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_schema_gate")
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: None,
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: hydra_core::CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn action(payload: HashMap<String, Value>) -> Action {
        let now = chrono::Utc::now();
        Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    fn policy(condition: HashMap<String, Value>) -> Policy {
        let now = chrono::Utc::now();
        Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "auto approve small ledger entries".to_string(),
            kind: PolicyKind::AutoApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::AnyAction,
            condition,
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn store_with_action_schema() -> SchemaRegistryStore {
        let mut store = SchemaRegistryStore::new();
        let now = chrono::Utc::now();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            }))
            .unwrap();
        store
    }

    fn store_with_evidence_schema() -> SchemaRegistryStore {
        let mut store = SchemaRegistryStore::new();
        let now = chrono::Utc::now();
        let schema = EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EvidencePayload(schema),
            }))
            .unwrap();
        store
    }

    fn evidence(kind: &str, data: HashMap<String, Value>) -> Evidence {
        let now = chrono::Utc::now();
        Evidence {
            id: EvidenceId::new(),
            tenant_id: None,
            source: EvidenceSource::System {
                name: "test".to_string(),
            },
            payload: EvidencePayload {
                kind: kind.to_string(),
                data,
            },
            reliability: Confidence::default(),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        }
    }

    fn store_with_claim_schema() -> SchemaRegistryStore {
        let mut store = SchemaRegistryStore::new();
        let now = chrono::Utc::now();
        let schema = ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: None,
            predicate: "is_stale".to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ClaimPredicate(schema),
            }))
            .unwrap();
        store
    }

    fn claim(object: ClaimObject) -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: None,
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.public.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object,
            confidence: Confidence::default(),
            status: ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn store_with_policy_schema() -> SchemaRegistryStore {
        let mut store = SchemaRegistryStore::new();
        let now = chrono::Utc::now();
        let schema = PolicyConditionSchema {
            id: SchemaId::new(),
            tenant_id: None,
            policy_kind: "AutoApproval".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("max_amount", ValueType::Float)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::PolicyCondition(schema),
            }))
            .unwrap();
        store
    }

    #[test]
    fn off_mode_allows_invalid_action() {
        let store = store_with_action_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::disabled();
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ActionProposed {
                action: action(payload),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_action() {
        let store = store_with_action_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ActionProposed {
                action: action(payload),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_allows_valid_action() {
        let store = store_with_action_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::Float(100.0));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ActionProposed {
                action: action(payload),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_reject_unknown_rejects_unknown_action_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_reject_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ActionProposed {
                action: action(HashMap::new()),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_allow_unknown_allows_unknown_action_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ActionProposed {
                action: action(HashMap::new()),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_policy_condition() {
        let store = store_with_policy_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::PolicyRegistered {
                policy: policy(HashMap::new()),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_allows_valid_policy_condition() {
        let store = store_with_policy_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut condition = HashMap::new();
        condition.insert("max_amount".to_string(), Value::Float(5000.0));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::PolicyRegistered {
                policy: policy(condition),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn permissive_mode_allows_invalid_event() {
        let store = store_with_action_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::new(SchemaGateConfig {
            mode: SchemaGateMode::Permissive,
            unknown_schema_policy: UnknownSchemaPolicy::Reject,
        });
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ActionProposed {
                action: action(HashMap::new()),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_evidence_payload() {
        let store = store_with_evidence_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        payload.insert("currency".to_string(), Value::String("USD".to_string()));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EvidenceAdded {
                evidence: evidence("bank_transaction", payload),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_allows_valid_evidence_payload() {
        let store = store_with_evidence_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Float(42.0));
        payload.insert("currency".to_string(), Value::String("USD".to_string()));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EvidenceAdded {
                evidence: evidence("bank_transaction", payload),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_reject_unknown_rejects_unknown_evidence_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_reject_unknown();
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Float(42.0));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EvidenceAdded {
                evidence: evidence("bank_transaction", payload),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_allow_unknown_allows_unknown_evidence_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Float(42.0));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EvidenceAdded {
                evidence: evidence("bank_transaction", payload),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_claim_object() {
        let store = store_with_claim_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ClaimProposed {
                claim: claim(ClaimObject::Value(Value::String("yes".to_string()))),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_allows_valid_claim() {
        let store = store_with_claim_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ClaimProposed {
                claim: claim(ClaimObject::Value(Value::Bool(true))),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_reject_unknown_rejects_unknown_claim_predicate_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_reject_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ClaimProposed {
                claim: claim(ClaimObject::Value(Value::Bool(true))),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_allow_unknown_allows_unknown_claim_predicate_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::ClaimProposed {
                claim: claim(ClaimObject::Value(Value::Bool(true))),
            },
        );
        assert!(result.is_ok());
    }

    fn store_with_entity_schema() -> SchemaRegistryStore {
        let mut store = SchemaRegistryStore::new();
        let now = chrono::Utc::now();
        let schema = EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("type_invoice"),
            name: "Invoice".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("invoice_number", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::optional("memo", ValueType::String),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EntityType(schema),
            }))
            .unwrap();
        store
    }

    #[test]
    fn strict_gate_allows_valid_node_create() {
        let store = store_with_entity_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::Float(100.0));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "type_invoice".to_string(),
                properties,
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_node_create() {
        let store = store_with_entity_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::String("bad".to_string()));
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "type_invoice".to_string(),
                properties,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_reject_unknown_rejects_unknown_node_type_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_reject_unknown();
        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "type_invoice".to_string(),
                properties,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_rejects_invalid_node_update_with_resolver() {
        let store = store_with_entity_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let node_id = NodeId::new();
        let target_id = node_id.clone();
        let resolver = move |id: &NodeId| {
            if id == &target_id {
                Some(TypeId::from_str("type_invoice"))
            } else {
                None
            }
        };
        let mut changes = HashMap::new();
        changes.insert("amount".to_string(), Value::String("bad".to_string()));
        let result = gate.validate_event_kind_with_node_resolver(
            &store,
            &validator,
            &EventKind::NodeUpdated {
                node_id: node_id.clone(),
                changes,
            },
            Some(&resolver),
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_allows_valid_node_update_with_resolver() {
        let store = store_with_entity_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let node_id = NodeId::new();
        let target_id = node_id.clone();
        let resolver = move |id: &NodeId| {
            if id == &target_id {
                Some(TypeId::from_str("type_invoice"))
            } else {
                None
            }
        };
        let mut changes = HashMap::new();
        changes.insert("amount".to_string(), Value::Float(125.0));
        let result = gate.validate_event_kind_with_node_resolver(
            &store,
            &validator,
            &EventKind::NodeUpdated {
                node_id: node_id.clone(),
                changes,
            },
            Some(&resolver),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn diagnostic_signal_contains_validation_errors() {
        let report = SchemaValidationReport::invalid(
            None,
            vec![SchemaValidationError::new(
                None,
                "amount",
                "missing required field",
            )],
        );
        let signal = SchemaGate::diagnostic_signal(&report).unwrap();
        match signal {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "schema.validation_failed");
                assert!(payload.contains_key("errors"));
            }
            other => panic!("expected Signal, got {other:?}"),
        }
    }

    // === Edge Gating Patch 1 ===

    fn store_with_edge_schema() -> SchemaRegistryStore {
        let mut store = SchemaRegistryStore::new();
        let now = chrono::Utc::now();
        let schema = hydra_core::EdgeTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("edge_depends_on"),
            name: "DependsOn".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("dependency_type", ValueType::String),
                FieldSchema::optional("confidence", ValueType::Float),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EdgeType(schema),
            }))
            .unwrap();
        store
    }

    #[test]
    fn strict_gate_allows_valid_edge_create() {
        let store = store_with_edge_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let mut properties = HashMap::new();
        properties.insert(
            "dependency_type".to_string(),
            Value::String("hard".to_string()),
        );
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EdgeCreated {
                edge_id: hydra_core::EdgeId::new(),
                source: NodeId::new(),
                target: NodeId::new(),
                type_id: "edge_depends_on".to_string(),
                properties,
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_edge_create() {
        let store = store_with_edge_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        // Missing the required `dependency_type` field.
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EdgeCreated {
                edge_id: hydra_core::EdgeId::new(),
                source: NodeId::new(),
                target: NodeId::new(),
                type_id: "edge_depends_on".to_string(),
                properties: HashMap::new(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_reject_unknown_blocks_edge_create_without_schema() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_reject_unknown();
        let mut properties = HashMap::new();
        properties.insert(
            "dependency_type".to_string(),
            Value::String("hard".to_string()),
        );
        let result = gate.validate_event_kind(
            &store,
            &validator,
            &EventKind::EdgeCreated {
                edge_id: hydra_core::EdgeId::new(),
                source: NodeId::new(),
                target: NodeId::new(),
                type_id: "edge_unknown".to_string(),
                properties,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn strict_gate_allows_valid_edge_update_with_resolver() {
        let store = store_with_edge_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let edge_id = hydra_core::EdgeId::new();
        // Resolver returns the registered type_id, simulating a
        // projection-backed lookup.
        let resolver = |id: &hydra_core::EdgeId| -> Option<TypeId> {
            if id == &edge_id {
                Some(TypeId::from_str("edge_depends_on"))
            } else {
                None
            }
        };
        let mut changes = HashMap::new();
        changes.insert("confidence".to_string(), Value::Float(0.95));
        let result = gate.validate_event_kind_with_resolvers(
            &store,
            &validator,
            &EventKind::EdgeUpdated {
                edge_id: edge_id.clone(),
                changes,
            },
            None,
            Some(&resolver),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn strict_gate_rejects_invalid_edge_update_with_resolver() {
        let store = store_with_edge_schema();
        let validator = SchemaValidator::new();
        let gate = SchemaGate::strict_allow_unknown();
        let edge_id = hydra_core::EdgeId::new();
        let resolver = |id: &hydra_core::EdgeId| -> Option<TypeId> {
            if id == &edge_id {
                Some(TypeId::from_str("edge_depends_on"))
            } else {
                None
            }
        };
        let mut changes = HashMap::new();
        changes.insert("bogus_field".to_string(), Value::String("x".to_string()));
        let result = gate.validate_event_kind_with_resolvers(
            &store,
            &validator,
            &EventKind::EdgeUpdated {
                edge_id: edge_id.clone(),
                changes,
            },
            None,
            Some(&resolver),
        );
        assert!(result.is_err());
    }
}
