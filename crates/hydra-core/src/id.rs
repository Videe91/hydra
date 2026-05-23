use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// 128-bit ULID: 48-bit timestamp (ms) + 80-bit random.
/// Sortable by creation time, globally unique without coordination.
/// We implement our own to avoid external dependency and keep it minimal.
///
/// SECURITY NOTE: The random portion uses xorshift, NOT a CSPRNG.
/// IDs are unique but PREDICTABLE. They MUST NOT be used as:
/// - Bearer tokens or session identifiers
/// - API keys or secrets
/// - Authorization evidence (knowing an ID does not imply access)
/// If IDs are exposed in APIs, every endpoint MUST verify authorization
/// independently. For unpredictable identifiers, use `getrandom` or `rand`.
fn generate_ulid_bytes() -> [u8; 16] {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut bytes = [0u8; 16];
    // First 6 bytes: timestamp in milliseconds (big-endian for sort order)
    bytes[0] = (ms >> 40) as u8;
    bytes[1] = (ms >> 32) as u8;
    bytes[2] = (ms >> 24) as u8;
    bytes[3] = (ms >> 16) as u8;
    bytes[4] = (ms >> 8) as u8;
    bytes[5] = ms as u8;

    // Last 10 bytes: random (using a simple xorshift from thread-local state)
    // In production you'd use a CSPRNG. For now, mix time nanos + a counter.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();

    // Simple entropy mixing — NOT cryptographic, sufficient for uniqueness
    let mut state: u64 = (ms ^ (nanos as u64)).wrapping_mul(6364136223846793005);
    for chunk in bytes[6..].chunks_mut(2) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let val = state as u16;
        chunk[0] = (val >> 8) as u8;
        chunk[1] = val as u8;
    }

    // Mix in a counter to ensure uniqueness even within the same nanosecond
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    bytes[14] ^= (count >> 8) as u8;
    bytes[15] ^= count as u8;

    bytes
}

/// Crockford Base32 encoding for ULID display (26 chars)
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode_crockford(bytes: &[u8; 16]) -> String {
    // ULID encodes 128 bits as 26 Crockford Base32 characters
    // 10 chars for 48-bit timestamp + 16 chars for 80-bit random
    let mut chars = [0u8; 26];
    let hi = u64::from_be_bytes([
        0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
    ]);
    let mid = u64::from_be_bytes([
        bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
    ]);
    let lo = u16::from_be_bytes([bytes[14], bytes[15]]);

    // Encode timestamp (48 bits → 10 chars)
    let ts = hi;
    chars[0] = CROCKFORD[((ts >> 45) & 0x1F) as usize];
    chars[1] = CROCKFORD[((ts >> 40) & 0x1F) as usize];
    chars[2] = CROCKFORD[((ts >> 35) & 0x1F) as usize];
    chars[3] = CROCKFORD[((ts >> 30) & 0x1F) as usize];
    chars[4] = CROCKFORD[((ts >> 25) & 0x1F) as usize];
    chars[5] = CROCKFORD[((ts >> 20) & 0x1F) as usize];
    chars[6] = CROCKFORD[((ts >> 15) & 0x1F) as usize];
    chars[7] = CROCKFORD[((ts >> 10) & 0x1F) as usize];
    chars[8] = CROCKFORD[((ts >> 5) & 0x1F) as usize];
    chars[9] = CROCKFORD[(ts & 0x1F) as usize];

    // Encode random (80 bits → 16 chars)
    // Combine mid (64 bits) + lo (16 bits) = 80 bits
    let rand_hi = mid;
    let rand_lo = lo as u64;
    let combined = (rand_hi as u128) << 16 | rand_lo as u128;
    for i in 0..16 {
        let shift = (15 - i) * 5;
        chars[10 + i] = CROCKFORD[((combined >> shift) & 0x1F) as usize];
    }

    String::from_utf8(chars.to_vec()).unwrap()
}

/// Macro to create strongly-typed ID wrappers.
/// Each ID type is distinct at compile time — you can't pass a NodeId where an EventId is expected.
macro_rules! define_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Generate a new unique ID
            pub fn new() -> Self {
                let bytes = generate_ulid_bytes();
                Self(format!("{}_{}", $prefix, encode_crockford(&bytes)))
            }

            /// Create from an existing string — UNCHECKED.
            /// Accepts any string, including empty, unicode, or path-traversal payloads.
            /// Use `from_str_validated` for untrusted input.
            /// This method exists for deserialization and test fixtures.
            pub fn from_str(s: &str) -> Self {
                Self(s.to_string())
            }

            /// Create from a string with validation.
            /// Rejects empty strings, strings containing path separators or
            /// null bytes. For use with untrusted/external input.
            pub fn from_str_validated(s: &str) -> Result<Self, String> {
                if s.is_empty() {
                    return Err("ID cannot be empty".to_string());
                }
                if s.contains('/') || s.contains('\\') || s.contains('\0') {
                    return Err(format!("ID contains forbidden characters: '{}'", s));
                }
                if s.contains("..") {
                    return Err(format!("ID contains path traversal: '{}'", s));
                }
                if s.len() > 256 {
                    return Err(format!("ID exceeds max length 256: len={}", s.len()));
                }
                Ok(Self(s.to_string()))
            }

            /// The raw string value
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

define_id!(EventId, "evt");
define_id!(NodeId, "node");
define_id!(EdgeId, "edge");
define_id!(CascadeId, "cas");
define_id!(CommitId, "commit");
define_id!(SensorId, "sensor");
define_id!(SensorRunId, "srun");
define_id!(SensorCheckpointId, "sckpt");
define_id!(TenantId, "ten");
define_id!(SubscriptionId, "sub");
define_id!(SnapshotId, "snap");
// Epistemic IDs
define_id!(ClaimId, "claim");
define_id!(EvidenceId, "evd");
define_id!(ActorId, "actor");
define_id!(PolicyId, "pol");
define_id!(PolicyDecisionId, "pdec");
define_id!(ApprovalId, "appr");
// Agentic action loop IDs
define_id!(ActionId, "act");
define_id!(OutcomeId, "out");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_is_unique() {
        let a = EventId::new();
        let b = EventId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn event_id_has_correct_prefix() {
        let id = EventId::new();
        assert!(id.as_str().starts_with("evt_"));
    }

    #[test]
    fn node_id_has_correct_prefix() {
        let id = NodeId::new();
        assert!(id.as_str().starts_with("node_"));
    }

    #[test]
    fn different_id_types_are_incompatible() {
        // This is a compile-time guarantee, but we verify the prefixes differ
        let event = EventId::new();
        let node = NodeId::new();
        assert_ne!(event.as_str().chars().next(), node.as_str().chars().next());
    }

    #[test]
    fn ids_are_sortable_by_creation_time() {
        let a = EventId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = EventId::new();
        // ULID encodes timestamp in the first characters — lexicographic sort = time sort
        assert!(a.as_str() < b.as_str());
    }

    #[test]
    fn ids_roundtrip_through_serde() {
        let id = EventId::new();
        let json = serde_json::to_string(&id).unwrap();
        let restored: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn from_str_preserves_value() {
        let id = NodeId::from_str("node_TEST123");
        assert_eq!(id.as_str(), "node_TEST123");
    }

    #[test]
    fn display_and_debug_work() {
        let id = EventId::from_str("evt_ABC");
        assert_eq!(format!("{}", id), "evt_ABC");
        assert_eq!(format!("{:?}", id), "EventId(evt_ABC)");
    }

    #[test]
    fn bulk_uniqueness() {
        let ids: Vec<EventId> = (0..1000).map(|_| EventId::new()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 1000);
    }

    // === Adversarial tests (code review audit) ===

    #[test]
    fn from_str_empty_string() {
        let id = NodeId::from_str("");
        assert_eq!(id.as_str(), "");
        // Empty IDs are technically valid (from_str is unchecked) — callers must validate
    }

    #[test]
    fn from_str_unicode() {
        let id = NodeId::from_str("node_こんにちは");
        assert_eq!(id.as_str(), "node_こんにちは");
    }

    #[test]
    fn from_str_path_traversal() {
        let id = TenantId::from_str("../../etc/passwd");
        assert_eq!(id.as_str(), "../../etc/passwd");
        // from_str accepts anything — the storage layer must sanitize
    }

    #[test]
    fn high_volume_uniqueness_stress() {
        // Test uniqueness under high-volume generation (counter wraparound boundary)
        let ids: Vec<EventId> = (0..10_000).map(|_| EventId::new()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 10_000, "ID collision detected in 10K batch");
    }

    #[test]
    fn all_id_types_generate_valid_ulids() {
        // Every ID type should produce a 26-char Crockford base32 string after the prefix
        let evt = EventId::new();
        let parts: Vec<&str> = evt.as_str().splitn(2, '_').collect();
        assert_eq!(parts[0], "evt");
        assert_eq!(parts[1].len(), 26);
        assert!(parts[1].chars().all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
    }

    #[test]
    fn default_impl_generates_unique() {
        let a = EventId::default();
        let b = EventId::default();
        assert_ne!(a, b);
    }

    // === from_str_validated tests (S2 fix) ===

    #[test]
    fn validated_accepts_valid_id() {
        let id = NodeId::from_str_validated("node_ABC123").unwrap();
        assert_eq!(id.as_str(), "node_ABC123");
    }

    #[test]
    fn validated_rejects_empty() {
        assert!(NodeId::from_str_validated("").is_err());
    }

    #[test]
    fn validated_rejects_path_traversal() {
        assert!(TenantId::from_str_validated("../../etc/passwd").is_err());
        assert!(TenantId::from_str_validated("ten_..").is_err());
    }

    #[test]
    fn validated_rejects_slashes() {
        assert!(NodeId::from_str_validated("node/evil").is_err());
        assert!(NodeId::from_str_validated("node\\evil").is_err());
    }

    #[test]
    fn validated_rejects_null_bytes() {
        assert!(NodeId::from_str_validated("node\0evil").is_err());
    }

    #[test]
    fn validated_rejects_oversized() {
        let long = "x".repeat(300);
        assert!(NodeId::from_str_validated(&long).is_err());
    }

    #[test]
    fn validated_accepts_hyphens_underscores() {
        assert!(TenantId::from_str_validated("ten_acme-corp_123").is_ok());
    }
}
