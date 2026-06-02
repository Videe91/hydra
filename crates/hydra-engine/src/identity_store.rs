//! Materialized Identity Graph store — Patch 29.
//!
//! Tiny passive store that mirrors
//! `EventKind::IdentityEntityCreated` into in-memory indexes:
//!
//! - `by_id` — direct lookup
//! - `by_kind` — keyed by `IdentityEntityKind::discriminant()`
//!   (a `String`, not the enum itself, so the `Custom(_)`
//!   variant doesn't need an `Ord` impl)
//! - `by_tenant` — `None`-tenanted entities skip this index
//! - `by_alias` — keyed by `IdentityAlias::index_key(tenant)`
//! - `by_canonical_key` — keyed by
//!   `"{tenant_or_sentinel}|{kind_discriminant}|{canonical_key}"`
//!   so canonical handles are unique per (tenant, kind)
//!
//! Rebuilt by `Hydra::recover_from_events` via `apply_event`;
//! restored from a snapshot body via direct insertion. Patch 29
//! ships only the create path — no update / merge / link / delete
//! events yet (those land in Patch 30+).
//!
//! ## Uniqueness contracts (enforced at create-time)
//!
//! - Alias uniqueness: `(tenant, source, namespace, normalized)`
//!   must map to AT MOST ONE entity. Returns `QueryError` if a
//!   second entity tries to claim a key already in use.
//!
//! - Canonical-key uniqueness: `(tenant, kind, canonical_key)`
//!   must map to AT MOST ONE entity. Same rule, same error
//!   shape. Prevents two semantically-identical entities from
//!   being created accidentally.
//!
//! Both uniqueness checks are LOCAL to the store (they don't
//! talk to the event log), so calling
//! `Hydra::create_identity_entity` is what enforces them at
//! the engine boundary. Direct `insert_entity` is used by
//! snapshot restore and bypasses the checks (the source data is
//! trusted by definition).

use chrono::{DateTime, Utc};
use hydra_core::{
    error::{HydraError, Result},
    Event, EventId, EventKind, IdentityAlias, IdentityEntity, IdentityEntityId,
    IdentityEntityKind, TenantId,
};
use std::collections::{BTreeSet, HashMap};

/// Patch 41 — outcome of `IdentityStore::add_alias`. Distinguishes
/// the freshly-attached case from the idempotent re-acceptance
/// case so the Hydra wrapper can SKIP event emission when the
/// alias was already present on the same entity (load-bearing —
/// duplicate `IdentityAliasAdded` events would pollute the audit
/// log and break replay determinism if a future patch tightens
/// alias-index semantics).
#[derive(Debug, Clone, PartialEq)]
pub enum AddAliasOutcome {
    /// Alias was new on this entity; the store mutated and the
    /// caller MUST ingest `EventKind::IdentityAliasAdded`.
    Added(IdentityEntity),
    /// Alias was already present on this entity (idempotent re-
    /// accept). Store was NOT mutated; caller MUST skip event
    /// emission. Pin via `accept_is_idempotent_no_duplicate_event`.
    AlreadyPresent(IdentityEntity),
}

/// Reserved sentinel for `None` tenant slots in the canonical-key
/// index. Same rationale as the alias-key sentinels exported by
/// `hydra_core::identity` — internal-only, never accept user
/// input that matches.
const CANON_TENANT_NONE_SENTINEL: &str = "__system__";

/// Materialized Identity Graph state. Built from the event log;
/// survives restart via snapshot + replay (same lifecycle as
/// `CausalCellStore` and `MicroModelStore`).
#[derive(Debug, Clone, Default)]
pub struct IdentityStore {
    by_id: HashMap<IdentityEntityId, IdentityEntity>,
    by_kind: HashMap<String, BTreeSet<IdentityEntityId>>,
    by_tenant: HashMap<TenantId, BTreeSet<IdentityEntityId>>,
    /// Keyed on `IdentityAlias::index_key(tenant)`.
    by_alias: HashMap<String, IdentityEntityId>,
    /// Keyed on
    /// `"{tenant_or_sentinel}|{kind_discriminant}|{canonical_key}"`.
    by_canonical_key: HashMap<String, IdentityEntityId>,
}

impl IdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    // === Counts ===

    pub fn entity_count(&self) -> usize {
        self.by_id.len()
    }

    // === Direct lookups ===

    pub fn entity(&self, id: &IdentityEntityId) -> Option<&IdentityEntity> {
        self.by_id.get(id)
    }

    pub fn all_entities(&self) -> impl Iterator<Item = &IdentityEntity> {
        self.by_id.values()
    }

    // === Indexed lookups ===

    /// All entities whose `kind` matches the given variant (via
    /// `kind.discriminant()`). Returns `Vec<&IdentityEntity>` so
    /// callers don't have to chain `.into_iter()` themselves —
    /// matches the `CausalCellStore::cells_with_kind` shape.
    pub fn entities_with_kind(
        &self,
        kind: &IdentityEntityKind,
    ) -> Vec<&IdentityEntity> {
        let key = kind.discriminant();
        self.by_kind
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    /// All entities scoped to a given tenant. `None`-tenanted
    /// (system-wide) entities are NOT returned — callers asking
    /// "for this tenant" want strict scoping. Mirrors P25's
    /// `CausalCellStore::cells_for_tenant`.
    pub fn entities_for_tenant(
        &self,
        tenant: &TenantId,
    ) -> Vec<&IdentityEntity> {
        self.by_tenant
            .get(tenant)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    /// Resolve an alias triple to its canonical entity.
    ///
    /// Strict tenant scoping: a tenanted query NEVER returns a
    /// `None`-tenanted (system) entity, and vice versa. The
    /// index keys on `IdentityAlias::index_key(tenant)`, which
    /// uses distinct sentinels for `None`-tenant vs tenant_x —
    /// so the two are physically separate slots.
    pub fn entity_by_alias(
        &self,
        tenant: Option<&TenantId>,
        source: &str,
        namespace: Option<&str>,
        normalized: &str,
    ) -> Option<&IdentityEntity> {
        let probe = IdentityAlias {
            source: source.to_string(),
            namespace: namespace.map(|s| s.to_string()),
            external_id: None,
            label: String::new(),
            normalized: normalized.to_string(),
        };
        let key = probe.index_key(tenant);
        let id = self.by_alias.get(&key)?;
        self.by_id.get(id)
    }

    // === Create path (with uniqueness checks) ===

    /// Validate-and-insert. Used by `Hydra::create_identity_entity`
    /// at the engine boundary. Returns `QueryError` for:
    ///
    /// - duplicate alias (`(tenant, source, namespace, normalized)`
    ///   already claimed)
    /// - duplicate canonical_key (`(tenant, kind, canonical_key)`
    ///   already claimed)
    /// - duplicate entity id (`id` already in the store —
    ///   shouldn't happen for ULID-minted ids but defensively
    ///   rejected)
    /// - bad alias (sentinel-collision, empty source/normalized
    ///   — see `IdentityAlias::validate`)
    pub fn create_entity(
        &mut self,
        entity: IdentityEntity,
    ) -> Result<IdentityEntity> {
        // 1. Reject duplicate id.
        if self.by_id.contains_key(&entity.id) {
            return Err(HydraError::QueryError(format!(
                "identity entity id already exists: {}",
                entity.id
            )));
        }

        // 2. Validate every alias.
        for alias in &entity.aliases {
            alias.validate().map_err(HydraError::QueryError)?;
        }

        // 3. Canonical-key uniqueness within (tenant, kind).
        let canon_key = canonical_index_key(
            entity.tenant_id.as_ref(),
            &entity.kind,
            &entity.canonical_key,
        );
        if let Some(existing) = self.by_canonical_key.get(&canon_key) {
            return Err(HydraError::QueryError(format!(
                "duplicate canonical_key '{}' for kind '{}' (tenant {:?}) — already mapped to entity {}",
                entity.canonical_key,
                entity.kind.discriminant(),
                entity
                    .tenant_id
                    .as_ref()
                    .map(|t| t.as_str())
                    .unwrap_or(CANON_TENANT_NONE_SENTINEL),
                existing
            )));
        }

        // 4. Alias uniqueness within (tenant, source, namespace,
        //    normalized). Each alias on the new entity is checked
        //    against the existing index BEFORE any insertion.
        for alias in &entity.aliases {
            let key = alias.index_key(entity.tenant_id.as_ref());
            if let Some(existing) = self.by_alias.get(&key) {
                return Err(HydraError::QueryError(format!(
                    "duplicate alias key '{key}' — already mapped to entity {existing}"
                )));
            }
        }

        // 5. All checks passed — insert.
        self.insert_entity(entity.clone());
        Ok(entity)
    }

    // === Patch 41 — Append alias to existing entity ===

    /// Append `alias` to an existing entity. Validates the alias
    /// (sentinels / empty), rejects cross-entity conflicts as a
    /// hard error, and is idempotent on same-entity duplicates
    /// (returns `AlreadyPresent` — caller must SKIP event
    /// emission).
    ///
    /// **Validate-before-mutate**: every check runs BEFORE any
    /// store mutation. A rejected call leaves the entity
    /// untouched. Mirrors the `create_entity` audit-log-on-
    /// rejection-stays-untouched contract.
    ///
    /// Targeted mutation (NOT a destructive `insert_entity`
    /// round-trip): we `get_mut` the entity, push the alias,
    /// update `updated_at` + `caused_by`, and insert the single
    /// new index entry in `by_alias`. By-kind / by-tenant /
    /// by-canonical-key indexes are unchanged because the
    /// canonical fields themselves are immutable.
    ///
    /// Used by `Hydra::accept_semantic_identity_match` AFTER all
    /// three trust gates pass; replayed verbatim by `apply_event`
    /// without re-running uniqueness checks (replay trusts the
    /// log — same stance as `IdentityEntityCreated`).
    pub fn add_alias(
        &mut self,
        entity_id: &IdentityEntityId,
        alias: IdentityAlias,
        updated_at: DateTime<Utc>,
        caused_by: Option<EventId>,
    ) -> Result<AddAliasOutcome> {
        // 1. Validate the alias up front (sentinel / empty
        //    rejection). Cheap, deterministic, and definitive.
        alias.validate().map_err(HydraError::QueryError)?;

        // 2. Load the entity. Missing entity → unified P32 / P33
        //    pattern: `"unknown identity entity: {id}"`.
        let entity = self.by_id.get(entity_id).ok_or_else(|| {
            HydraError::QueryError(format!(
                "unknown identity entity: {entity_id}"
            ))
        })?;

        // 3. Idempotent same-entity dedup: if the alias is
        //    already on this entity (matched by the full
        //    structural equality of all 5 fields), return
        //    AlreadyPresent so the caller skips event emission.
        //    Belt-and-suspenders: also check the index key (a
        //    same-tenant alias with identical (source, namespace,
        //    normalized) but a different `label` / `external_id`
        //    would NOT be a structural match but WOULD collide
        //    in `by_alias`).
        let key = alias.index_key(entity.tenant_id.as_ref());
        let alias_already_on_this_entity = entity
            .aliases
            .iter()
            .any(|a| a.index_key(entity.tenant_id.as_ref()) == key);
        if alias_already_on_this_entity {
            return Ok(AddAliasOutcome::AlreadyPresent(entity.clone()));
        }

        // 4. Cross-entity alias conflict — hard error. The
        //    by_alias index already maps this key to a DIFFERENT
        //    entity. Mirrors `create_entity` line 206-209 exactly.
        if let Some(existing) = self.by_alias.get(&key) {
            return Err(HydraError::QueryError(format!(
                "alias '{key}' already mapped to a different entity \
                 {existing} — operator must merge entities through a \
                 SameAs workflow (P43+), not re-point aliases"
            )));
        }

        // 5. All checks passed — append the alias + update
        //    indexes + bump `updated_at`. Targeted mutation
        //    avoids the destructive `insert_entity` round-trip.
        let entity_id_clone = entity_id.clone();
        if let Some(e) = self.by_id.get_mut(&entity_id_clone) {
            e.aliases.push(alias.clone());
            e.updated_at = updated_at;
            e.caused_by = caused_by;
        }
        self.by_alias.insert(key, entity_id_clone.clone());

        // Return the updated entity. Safe to unwrap — we just
        // mutated it.
        let updated = self
            .by_id
            .get(&entity_id_clone)
            .expect("entity present (just mutated)")
            .clone();
        Ok(AddAliasOutcome::Added(updated))
    }

    // === Event ingest ===

    /// Apply one event. Patch 29 handles `IdentityEntityCreated`;
    /// Patch 41 adds `IdentityAliasAdded` replay. Replay does NOT
    /// re-run uniqueness or trust checks — the original Hydra
    /// method already validated; replay is a faithful state
    /// rebuild. Same pattern other stores follow.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::IdentityEntityCreated { entity } => {
                self.insert_entity(entity.clone());
            }
            EventKind::IdentityAliasAdded {
                entity_id,
                alias,
                updated_at,
                caused_by,
                ..
            } => {
                // Replay branch — trust the log. Append + index
                // unconditionally; no validation. If the
                // referenced entity is somehow missing on replay
                // (genuine engine corruption), silently skip
                // rather than error — mirrors the
                // `IdentityEntityCreated` no-op stance.
                if let Some(entity) = self.by_id.get_mut(entity_id) {
                    let key = alias.index_key(entity.tenant_id.as_ref());
                    entity.aliases.push(alias.clone());
                    entity.updated_at = *updated_at;
                    entity.caused_by = caused_by.clone();
                    self.by_alias.insert(key, entity_id.clone());
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn apply_events<'a>(
        &mut self,
        events: impl IntoIterator<Item = &'a Event>,
    ) -> Result<()> {
        for event in events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    // === Snapshot restore / replay helper ===

    /// Insert an entity directly, bypassing uniqueness checks.
    /// Used by `Hydra::recover_from_snapshot_body_and_replay` to
    /// seed the store from a snapshot body's `identity_entities`
    /// vec without re-emitting `IdentityEntityCreated` events,
    /// and by `apply_event` during replay. Idempotent on
    /// re-insert: removes prior index entries before installing
    /// the new ones.
    pub fn insert_entity(&mut self, entity: IdentityEntity) {
        let id = entity.id.clone();
        if let Some(existing) = self.by_id.remove(&id) {
            self.remove_indexes(&existing);
        }
        self.add_indexes(&entity);
        self.by_id.insert(id, entity);
    }

    fn add_indexes(&mut self, entity: &IdentityEntity) {
        let kind_key = entity.kind.discriminant();
        self.by_kind
            .entry(kind_key)
            .or_default()
            .insert(entity.id.clone());
        if let Some(tenant) = &entity.tenant_id {
            self.by_tenant
                .entry(tenant.clone())
                .or_default()
                .insert(entity.id.clone());
        }
        for alias in &entity.aliases {
            let key = alias.index_key(entity.tenant_id.as_ref());
            self.by_alias.insert(key, entity.id.clone());
        }
        let canon_key = canonical_index_key(
            entity.tenant_id.as_ref(),
            &entity.kind,
            &entity.canonical_key,
        );
        self.by_canonical_key.insert(canon_key, entity.id.clone());
    }

    fn remove_indexes(&mut self, entity: &IdentityEntity) {
        let kind_key = entity.kind.discriminant();
        if let Some(set) = self.by_kind.get_mut(&kind_key) {
            set.remove(&entity.id);
            if set.is_empty() {
                self.by_kind.remove(&kind_key);
            }
        }
        if let Some(tenant) = &entity.tenant_id {
            if let Some(set) = self.by_tenant.get_mut(tenant) {
                set.remove(&entity.id);
                if set.is_empty() {
                    self.by_tenant.remove(tenant);
                }
            }
        }
        for alias in &entity.aliases {
            let key = alias.index_key(entity.tenant_id.as_ref());
            self.by_alias.remove(&key);
        }
        let canon_key = canonical_index_key(
            entity.tenant_id.as_ref(),
            &entity.kind,
            &entity.canonical_key,
        );
        self.by_canonical_key.remove(&canon_key);
    }
}

/// Compose the canonical-key index key.
///
/// Format: `"{tenant_or_sentinel}|{kind_discriminant}|{canonical_key}"`.
/// Mirrors the alias-key composition style so the two indexes
/// stay visually parallel.
fn canonical_index_key(
    tenant: Option<&TenantId>,
    kind: &IdentityEntityKind,
    canonical_key: &str,
) -> String {
    format!(
        "{}|{}|{}",
        tenant
            .map(|t| t.as_str())
            .unwrap_or(CANON_TENANT_NONE_SENTINEL),
        kind.discriminant(),
        canonical_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{ActorId, Confidence};
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_ops")
    }

    /// Build a minimal `IdentityEntity` for tests.
    fn make_entity(
        tenant_id: Option<TenantId>,
        kind: IdentityEntityKind,
        canonical_key: &str,
        aliases: Vec<IdentityAlias>,
    ) -> IdentityEntity {
        let now = chrono::Utc::now();
        IdentityEntity {
            id: IdentityEntityId::new(),
            tenant_id,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases,
            confidence: Confidence::new(1.0),
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn snowflake_alias(ns: &str, table: &str) -> IdentityAlias {
        IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some(ns.to_string()),
            external_id: Some(format!("{ns}.{table}").to_uppercase()),
            label: format!("{ns}.{table}").to_uppercase(),
            normalized: format!("{}.{}", ns.to_lowercase(), table.to_lowercase()),
        }
    }

    #[test]
    fn creates_and_reads_entity() {
        let mut store = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_a");
        let entity = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let id = entity.id.clone();
        let inserted = store.create_entity(entity).unwrap();
        assert_eq!(store.entity_count(), 1);
        assert_eq!(store.entity(&id), Some(&inserted));
    }

    #[test]
    fn indexes_by_kind() {
        let mut store = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_a");
        let dataset = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let service = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Service,
            "service/payments_api",
            vec![],
        );
        store.create_entity(dataset.clone()).unwrap();
        store.create_entity(service.clone()).unwrap();
        let datasets = store
            .entities_with_kind(&IdentityEntityKind::Dataset);
        assert_eq!(datasets.len(), 1);
        assert_eq!(datasets[0].id, dataset.id);
        let services = store
            .entities_with_kind(&IdentityEntityKind::Service);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].id, service.id);
    }

    #[test]
    fn indexes_by_alias() {
        let mut store = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_a");
        let entity = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let id = entity.id.clone();
        store.create_entity(entity).unwrap();
        let found = store
            .entity_by_alias(
                Some(&tenant),
                "snowflake",
                Some("analytics"),
                "analytics.revenue_daily",
            )
            .expect("alias resolves");
        assert_eq!(found.id, id);
    }

    #[test]
    fn rejects_duplicate_alias_same_tenant() {
        let mut store = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_a");
        let a = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/a",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let b = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/b",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        store.create_entity(a).unwrap();
        match store.create_entity(b) {
            Err(HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("duplicate alias"),
                    "expected duplicate-alias error, got {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn allows_same_alias_under_different_tenant() {
        let mut store = IdentityStore::new();
        let tenant_a = TenantId::from_str("tenant_a");
        let tenant_b = TenantId::from_str("tenant_b");
        let a = make_entity(
            Some(tenant_a),
            IdentityEntityKind::Dataset,
            "dataset/x",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let b = make_entity(
            Some(tenant_b),
            IdentityEntityKind::Dataset,
            "dataset/x",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        store.create_entity(a).unwrap();
        // Same alias triple, different tenant → different
        // index_key → no conflict.
        store.create_entity(b).unwrap();
        assert_eq!(store.entity_count(), 2);
    }

    #[test]
    fn rejects_duplicate_canonical_key_same_tenant() {
        let mut store = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_a");
        let a = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![],
        );
        let b = make_entity(
            Some(tenant),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("ops", "different_thing")],
        );
        store.create_entity(a).unwrap();
        match store.create_entity(b) {
            Err(HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("duplicate canonical_key"),
                    "expected duplicate-canonical-key error, got {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn entity_by_alias_none_tenant_strict_isolation() {
        // LOAD-BEARING pin: a system (`None`-tenanted) entity
        // must NOT be visible to a tenanted alias query. The
        // index sentinels guarantee distinct slots; this pin
        // catches any future refactor that "unifies" them.
        let mut store = IdentityStore::new();
        let system = make_entity(
            None,
            IdentityEntityKind::Source,
            "source/snowflake_prod",
            vec![IdentityAlias {
                source: "snowflake".to_string(),
                namespace: None,
                external_id: None,
                label: "snowflake-prod".to_string(),
                normalized: "snowflake-prod".to_string(),
            }],
        );
        store.create_entity(system).unwrap();
        let tenant = TenantId::from_str("tenant_a");
        // Tenanted query → none.
        assert!(store
            .entity_by_alias(
                Some(&tenant),
                "snowflake",
                None,
                "snowflake-prod",
            )
            .is_none());
        // None query → finds it.
        assert!(store
            .entity_by_alias(None, "snowflake", None, "snowflake-prod",)
            .is_some());
    }

    #[test]
    fn apply_event_replays_entity() {
        // `apply_event` is the replay path. Direct ingestion
        // via `apply_event` (bypassing `create_entity`) must
        // produce the same indexed state.
        let mut store = IdentityStore::new();
        let entity = make_entity(
            Some(TenantId::from_str("tenant_a")),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let id = entity.id.clone();
        let event = Event::trigger(EventKind::IdentityEntityCreated {
            entity,
        });
        store.apply_event(&event).unwrap();
        assert_eq!(store.entity_count(), 1);
        assert!(store.entity(&id).is_some());
    }

    #[test]
    fn rejects_invalid_alias_sentinel() {
        // `IdentityAlias::validate` is invoked inside
        // `create_entity` so a caller can't smuggle the
        // `__system__` sentinel as a source name.
        let mut store = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_a");
        let entity = make_entity(
            Some(tenant),
            IdentityEntityKind::Dataset,
            "dataset/x",
            vec![IdentityAlias {
                source: "__system__".to_string(),
                namespace: None,
                external_id: None,
                label: "x".to_string(),
                normalized: "x".to_string(),
            }],
        );
        match store.create_entity(entity) {
            Err(HydraError::QueryError(msg)) => {
                assert!(msg.contains("reserved sentinel"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }
}
