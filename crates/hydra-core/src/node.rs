use crate::event::Value;
use crate::id::{NodeId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Metadata common to every node, managed by the engine (not the domain).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeMeta {
    pub id: NodeId,
    pub type_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u64,
    pub alive: bool,
    /// Tenant that owns this node, stamped from the creating Event's
    /// envelope at projection-apply time (Multi-tenant Patch 2B).
    /// `serde(default)` keeps snapshots written before Patch 2B
    /// loadable — older bodies deserialize this as `None` and the
    /// engine treats them as system/global nodes.
    #[serde(default)]
    pub tenant_id: Option<TenantId>,
}

impl NodeMeta {
    pub fn new(id: NodeId, type_id: String) -> Self {
        Self::new_for_tenant(id, type_id, None)
    }

    /// Construct a NodeMeta scoped to a tenant. The projection's
    /// `NodeCreated` handler uses this so the resulting `Node` carries
    /// the same tenant as the `Event` envelope.
    pub fn new_for_tenant(id: NodeId, type_id: String, tenant_id: Option<TenantId>) -> Self {
        let now = Utc::now();
        Self {
            id,
            type_id,
            created_at: now,
            updated_at: now,
            version: 1,
            alive: true,
            tenant_id,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
        self.version += 1;
    }
}

/// A stored node in the graph: engine-managed metadata + domain-specific properties.
///
/// Properties are stored as HashMap<String, Value> for flexibility.
/// Domain-specific typed access is provided by the NodeType trait
/// and its as_any() downcast pattern.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub meta: NodeMeta,
    pub properties: HashMap<String, Value>,
}

impl Node {
    pub fn new(id: NodeId, type_id: String, properties: HashMap<String, Value>) -> Self {
        Self::new_for_tenant(id, type_id, properties, None)
    }

    pub fn new_for_tenant(
        id: NodeId,
        type_id: String,
        properties: HashMap<String, Value>,
        tenant_id: Option<TenantId>,
    ) -> Self {
        Self {
            meta: NodeMeta::new_for_tenant(id, type_id, tenant_id),
            properties,
        }
    }

    pub fn id(&self) -> &NodeId {
        &self.meta.id
    }

    pub fn type_id(&self) -> &str {
        &self.meta.type_id
    }

    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.meta.tenant_id.as_ref()
    }

    pub fn is_alive(&self) -> bool {
        self.meta.alive
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.properties.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.properties.get(key).and_then(|v| v.as_str())
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.properties.get(key).and_then(|v| v.as_i64())
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.properties.get(key).and_then(|v| v.as_f64())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.properties.get(key).and_then(|v| v.as_bool())
    }

    /// Apply property changes. Returns the set of keys that actually changed.
    pub fn apply_changes(&mut self, changes: &HashMap<String, Value>) -> Vec<String> {
        let mut changed_keys = Vec::new();
        for (key, new_val) in changes {
            let is_new = match self.properties.get(key) {
                Some(old_val) => old_val != new_val,
                None => true,
            };
            if is_new {
                self.properties.insert(key.clone(), new_val.clone());
                changed_keys.push(key.clone());
            }
        }
        if !changed_keys.is_empty() {
            self.meta.touch();
        }
        changed_keys
    }

    /// Mark this node as deleted
    pub fn delete(&mut self) {
        self.meta.alive = false;
        self.meta.touch();
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}, v{}, {})",
            self.meta.type_id,
            self.meta.id,
            self.meta.version,
            if self.meta.alive { "alive" } else { "dead" }
        )
    }
}

/// Trait for domain-specific node validation.
/// Domain verticals implement this to enforce invariants.
///
/// Example: An Ec2InstanceValidator ensures "instance_id" exists and is a string.
pub trait NodeValidator: Send + Sync {
    /// The type_id this validator handles
    fn type_id(&self) -> &'static str;

    /// Validate that properties are correct for this node type.
    /// Called on NodeCreated and NodeUpdated events.
    fn validate(&self, properties: &HashMap<String, Value>) -> crate::error::Result<()>;

    /// Return the set of required property keys
    fn required_properties(&self) -> Vec<&'static str> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Value;

    #[test]
    fn node_creation() {
        let id = NodeId::new();
        let node = Node::new(
            id.clone(),
            "ec2_instance".to_string(),
            HashMap::from([("state".to_string(), Value::String("running".to_string()))]),
        );

        assert_eq!(node.id(), &id);
        assert_eq!(node.type_id(), "ec2_instance");
        assert!(node.is_alive());
        assert_eq!(node.meta.version, 1);
        assert_eq!(node.get_str("state"), Some("running"));
    }

    #[test]
    fn apply_changes_tracks_what_changed() {
        let mut node = Node::new(
            NodeId::new(),
            "test".to_string(),
            HashMap::from([
                ("a".to_string(), Value::Int(1)),
                ("b".to_string(), Value::Int(2)),
            ]),
        );

        let changes = HashMap::from([
            ("a".to_string(), Value::Int(1)), // same value — NOT a change
            ("b".to_string(), Value::Int(3)), // different — IS a change
            ("c".to_string(), Value::Int(4)), // new key — IS a change
        ]);

        let changed = node.apply_changes(&changes);
        assert_eq!(changed.len(), 2);
        assert!(changed.contains(&"b".to_string()));
        assert!(changed.contains(&"c".to_string()));
        assert_eq!(node.meta.version, 2);
    }

    #[test]
    fn apply_no_changes_doesnt_bump_version() {
        let mut node = Node::new(
            NodeId::new(),
            "test".to_string(),
            HashMap::from([("a".to_string(), Value::Int(1))]),
        );

        let changes = HashMap::from([("a".to_string(), Value::Int(1))]); // same
        let changed = node.apply_changes(&changes);
        assert!(changed.is_empty());
        assert_eq!(node.meta.version, 1); // NOT bumped
    }

    #[test]
    fn delete_marks_dead_and_bumps_version() {
        let mut node = Node::new(NodeId::new(), "test".to_string(), HashMap::new());
        assert!(node.is_alive());
        assert_eq!(node.meta.version, 1);

        node.delete();
        assert!(!node.is_alive());
        assert_eq!(node.meta.version, 2);
    }

    #[test]
    fn display_format() {
        let node = Node::new(
            NodeId::from_str("node_ABC"),
            "ec2".to_string(),
            HashMap::new(),
        );
        let display = format!("{}", node);
        assert!(display.contains("ec2"));
        assert!(display.contains("node_ABC"));
        assert!(display.contains("v1"));
        assert!(display.contains("alive"));
    }

    #[test]
    fn serde_roundtrip() {
        let node = Node::new(
            NodeId::from_str("node_SER"),
            "rds".to_string(),
            HashMap::from([
                ("engine".to_string(), Value::String("postgres".to_string())),
                ("port".to_string(), Value::Int(5432)),
            ]),
        );

        let json = serde_json::to_string(&node).unwrap();
        let restored: Node = serde_json::from_str(&json).unwrap();

        assert_eq!(node.id(), restored.id());
        assert_eq!(node.type_id(), restored.type_id());
        assert_eq!(node.properties, restored.properties);
    }
}
