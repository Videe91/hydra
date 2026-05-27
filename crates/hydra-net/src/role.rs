//! V2 polish #6 — shared HTTP-runtime role + mutable role state.
//!
//! Lives in `hydra-net` so both:
//!   - hydra-net's `replication_role_router` (`POST/GET /replication/role`)
//!   - hydra-api's `role_middleware`
//! can read and mutate the same atomic. hydra-api re-exports
//! [`RuntimeRole`] from here for backward compat with code that
//! imported from `hydra_api::security::RuntimeRole`.
//!
//! ## Design
//!
//! Pre-polish-#6, `RoleState` was `Copy` with the role value baked
//! in at server build time, and the role middleware layer was
//! conditionally installed only when role=Follower. That made the
//! role immutable for the lifetime of the server.
//!
//! Polish #6 switches to:
//!   - Always-on role layer (unconditional, single atomic load on
//!     the Leader hot path)
//!   - `RoleState` wraps `Arc<AtomicU8>` — shared across the
//!     middleware AND the POST/GET role-flip handlers
//!   - `set()` is `Ordering::Release`, `get()` is `Ordering::Acquire`
//!     so middleware sees a flip immediately after the handler
//!     returns
//!
//! The atomic-load cost on Leader is negligible against the rest
//! of the middleware stack.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// HTTP-layer role. Distinct from `hydra_engine::EngineRole`
/// (engine-layer write guard from polish #5) — the two are
/// deliberately separate types in separate crates. The role-flip
/// admin route in this patch keeps them in lockstep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeRole {
    Leader,
    Follower,
}

impl Default for RuntimeRole {
    fn default() -> Self {
        Self::Leader
    }
}

const LEADER_U8: u8 = 0;
const FOLLOWER_U8: u8 = 1;

fn role_to_u8(role: RuntimeRole) -> u8 {
    match role {
        RuntimeRole::Leader => LEADER_U8,
        RuntimeRole::Follower => FOLLOWER_U8,
    }
}

fn u8_to_role(value: u8) -> RuntimeRole {
    match value {
        FOLLOWER_U8 => RuntimeRole::Follower,
        _ => RuntimeRole::Leader,
    }
}

/// Shared, mutable runtime role. Clone is cheap (Arc bump).
///
/// `get()` is an `Acquire` load — middleware sees flips immediately
/// after a `set()` returns. `set()` is a `Release` store.
#[derive(Debug, Clone)]
pub struct RoleState {
    role: Arc<AtomicU8>,
}

impl RoleState {
    pub fn new(role: RuntimeRole) -> Self {
        Self {
            role: Arc::new(AtomicU8::new(role_to_u8(role))),
        }
    }

    pub fn get(&self) -> RuntimeRole {
        u8_to_role(self.role.load(Ordering::Acquire))
    }

    pub fn set(&self, role: RuntimeRole) {
        self.role.store(role_to_u8(role), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_state_round_trips() {
        let state = RoleState::new(RuntimeRole::Leader);
        assert_eq!(state.get(), RuntimeRole::Leader);
        state.set(RuntimeRole::Follower);
        assert_eq!(state.get(), RuntimeRole::Follower);
        state.set(RuntimeRole::Leader);
        assert_eq!(state.get(), RuntimeRole::Leader);
    }

    #[test]
    fn role_state_clone_shares_storage() {
        let a = RoleState::new(RuntimeRole::Leader);
        let b = a.clone();
        a.set(RuntimeRole::Follower);
        assert_eq!(b.get(), RuntimeRole::Follower);
    }

    #[test]
    fn runtime_role_serde_lowercase() {
        assert_eq!(
            serde_json::to_string(&RuntimeRole::Leader).unwrap(),
            "\"leader\""
        );
        assert_eq!(
            serde_json::to_string(&RuntimeRole::Follower).unwrap(),
            "\"follower\""
        );
        let parsed: RuntimeRole = serde_json::from_str("\"follower\"").unwrap();
        assert_eq!(parsed, RuntimeRole::Follower);
    }
}
