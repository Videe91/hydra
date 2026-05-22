use crate::event::Value;
use crate::id::{EdgeId, NodeId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Metadata common to every edge, managed by the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeMeta {
    pub id: EdgeId,
    pub type_id: String,
    pub source: NodeId,
    pub target: NodeId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u64,
    pub alive: bool,
}

impl EdgeMeta {
    pub fn new(id: EdgeId, type_id: String, source: NodeId, target: NodeId) -> Self {
        let now = Utc::now();
        Self {
            id,
            type_id,
            source,
            target,
            created_at: now,
            updated_at: now,
            version: 1,
            alive: true,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
        self.version += 1;
    }
}

/// A stored edge in the graph.
/// Edges are first-class entities with their own properties.
/// "DependsOn" edge might have properties: dependency_type, confidence, discovered_at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub meta: EdgeMeta,
    pub properties: HashMap<String, Value>,
}

impl Edge {
    pub fn new(
        id: EdgeId,
        type_id: String,
        source: NodeId,
        target: NodeId,
        properties: HashMap<String, Value>,
    ) -> Self {
        Self {
            meta: EdgeMeta::new(id, type_id, source, target),
            properties,
        }
    }

    pub fn id(&self) -> &EdgeId {
        &self.meta.id
    }

    pub fn type_id(&self) -> &str {
        &self.meta.type_id
    }

    pub fn source(&self) -> &NodeId {
        &self.meta.source
    }

    pub fn target(&self) -> &NodeId {
        &self.meta.target
    }

    pub fn is_alive(&self) -> bool {
        self.meta.alive
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.properties.get(key)
    }

    /// Apply property changes. Returns keys that actually changed.
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

    pub fn delete(&mut self) {
        self.meta.alive = false;
        self.meta.touch();
    }
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}: {} → {})",
            self.meta.type_id, self.meta.id, self.meta.source, self.meta.target,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Value;

    #[test]
    fn edge_creation() {
        let src = NodeId::new();
        let tgt = NodeId::new();
        let edge = Edge::new(
            EdgeId::new(),
            "depends_on".to_string(),
            src.clone(),
            tgt.clone(),
            HashMap::from([("confidence".to_string(), Value::Float(0.95))]),
        );

        assert_eq!(edge.source(), &src);
        assert_eq!(edge.target(), &tgt);
        assert_eq!(edge.type_id(), "depends_on");
        assert!(edge.is_alive());
        assert_eq!(edge.get("confidence").and_then(|v| v.as_f64()), Some(0.95));
    }

    #[test]
    fn edge_apply_changes() {
        let mut edge = Edge::new(
            EdgeId::new(),
            "test".to_string(),
            NodeId::new(),
            NodeId::new(),
            HashMap::from([("weight".to_string(), Value::Float(1.0))]),
        );

        let changes = HashMap::from([("weight".to_string(), Value::Float(2.0))]);
        let changed = edge.apply_changes(&changes);
        assert_eq!(changed, vec!["weight".to_string()]);
        assert_eq!(edge.meta.version, 2);
    }

    #[test]
    fn edge_delete() {
        let mut edge = Edge::new(
            EdgeId::new(),
            "test".to_string(),
            NodeId::new(),
            NodeId::new(),
            HashMap::new(),
        );
        edge.delete();
        assert!(!edge.is_alive());
    }

    #[test]
    fn edge_display() {
        let src = NodeId::from_str("node_A");
        let tgt = NodeId::from_str("node_B");
        let edge = Edge::new(
            EdgeId::from_str("edge_1"),
            "depends_on".to_string(),
            src,
            tgt,
            HashMap::new(),
        );
        let display = format!("{}", edge);
        assert!(display.contains("depends_on"));
        assert!(display.contains("node_A"));
        assert!(display.contains("node_B"));
    }

    #[test]
    fn edge_serde_roundtrip() {
        let edge = Edge::new(
            EdgeId::from_str("edge_SER"),
            "protects".to_string(),
            NodeId::from_str("node_SNAP"),
            NodeId::from_str("node_EC2"),
            HashMap::from([("verified".to_string(), Value::Bool(true))]),
        );

        let json = serde_json::to_string(&edge).unwrap();
        let restored: Edge = serde_json::from_str(&json).unwrap();

        assert_eq!(edge.id(), restored.id());
        assert_eq!(edge.source(), restored.source());
        assert_eq!(edge.target(), restored.target());
        assert_eq!(edge.properties, restored.properties);
    }
}
