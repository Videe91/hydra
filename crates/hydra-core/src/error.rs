use crate::id::{EdgeId, EventId, NodeId};
use std::fmt;

/// All Hydra errors. Typed, specific, actionable.
#[derive(Debug)]
pub enum HydraError {
    // Node errors
    NodeNotFound(NodeId),
    NodeAlreadyExists(NodeId),
    InvalidNodeType { type_id: String, reason: String },
    NodeValidationFailed { node_id: NodeId, reason: String },

    // Edge errors
    EdgeNotFound(EdgeId),
    EdgeAlreadyExists(EdgeId),
    InvalidEdgeEndpoints { source: NodeId, target: NodeId },
    EdgeValidationFailed { edge_id: EdgeId, reason: String },

    // Event errors
    EventNotFound(EventId),
    CausalParentNotFound { event_id: EventId, parent_id: EventId },
    CascadeDepthExceeded { max: u32, actual: u32 },
    CascadeCycleDetected { event_id: EventId },

    // Query errors
    QueryError(String),

    // Serialization errors
    SerializationError(String),

    // Storage errors
    StorageError(String),

    // Resource limit errors
    ResourceExhausted { resource: String, limit: usize, current: usize },
}

impl fmt::Display for HydraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeNotFound(id) => write!(f, "node not found: {}", id),
            Self::NodeAlreadyExists(id) => write!(f, "node already exists: {}", id),
            Self::InvalidNodeType { type_id, reason } => {
                write!(f, "invalid node type '{}': {}", type_id, reason)
            }
            Self::NodeValidationFailed { node_id, reason } => {
                write!(f, "node validation failed for {}: {}", node_id, reason)
            }
            Self::EdgeNotFound(id) => write!(f, "edge not found: {}", id),
            Self::EdgeAlreadyExists(id) => write!(f, "edge already exists: {}", id),
            Self::InvalidEdgeEndpoints { source, target } => {
                write!(f, "invalid edge: source {} or target {} does not exist", source, target)
            }
            Self::EdgeValidationFailed { edge_id, reason } => {
                write!(f, "edge validation failed for {}: {}", edge_id, reason)
            }
            Self::EventNotFound(id) => write!(f, "event not found: {}", id),
            Self::CausalParentNotFound { event_id, parent_id } => {
                write!(
                    f,
                    "causal parent not found: event {} references non-existent parent {}",
                    event_id, parent_id
                )
            }
            Self::CascadeDepthExceeded { max, actual } => {
                write!(f, "cascade depth exceeded maximum of {}: reached {}", max, actual)
            }
            Self::CascadeCycleDetected { event_id } => {
                write!(f, "cascade cycle detected at event {}", event_id)
            }
            Self::QueryError(msg) => write!(f, "query error: {}", msg),
            Self::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            Self::StorageError(msg) => write!(f, "storage error: {}", msg),
            Self::ResourceExhausted { resource, limit, current } => {
                write!(f, "resource exhausted: {} limit is {}, currently at {}", resource, limit, current)
            }
        }
    }
}

impl std::error::Error for HydraError {}

pub type Result<T> = std::result::Result<T, HydraError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display_correctly() {
        let id = NodeId::from_str("node_ABC");
        let err = HydraError::NodeNotFound(id);
        assert_eq!(err.to_string(), "node not found: node_ABC");
    }

    #[test]
    fn cascade_depth_error_shows_values() {
        let err = HydraError::CascadeDepthExceeded {
            max: 100,
            actual: 101,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("101"));
    }

    #[test]
    fn result_type_works() {
        fn might_fail(exists: bool) -> Result<()> {
            if exists {
                Ok(())
            } else {
                Err(HydraError::NodeNotFound(NodeId::from_str("node_X")))
            }
        }
        assert!(might_fail(true).is_ok());
        assert!(might_fail(false).is_err());
    }

    #[test]
    fn edge_endpoint_error() {
        let err = HydraError::InvalidEdgeEndpoints {
            source: NodeId::from_str("node_A"),
            target: NodeId::from_str("node_B"),
        };
        let msg = err.to_string();
        assert!(msg.contains("node_A"));
        assert!(msg.contains("node_B"));
    }

    #[test]
    fn causal_parent_error() {
        let err = HydraError::CausalParentNotFound {
            event_id: EventId::from_str("evt_1"),
            parent_id: EventId::from_str("evt_0"),
        };
        let msg = err.to_string();
        assert!(msg.contains("evt_1"));
        assert!(msg.contains("evt_0"));
    }
}
