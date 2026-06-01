//! Materialized Identity Graph relationship store — Patch 37.
//!
//! Tiny passive store that mirrors `EventKind::IdentityLinkCreated`
//! into in-memory indexes. Companion to `IdentityStore` (P29) —
//! P29 holds canonical entities; P37 holds the relationships
//! between them.
//!
//! ## Indexes
//!
//! - `by_id` — direct lookup by `IdentityLinkId`
//! - `by_kind` — keyed by `IdentityLinkKind::discriminant()`
//!   (a `String`, not the enum itself, so the `Custom(_)`
//!   variant doesn't need an `Ord` impl)
//! - `by_from` — keyed by `from_entity_id`, holds all outgoing
//!   links from that entity
//! - `by_to` — keyed by `to_entity_id`, holds all incoming links
//!   to that entity
//! - `by_tenant` — `None`-tenanted links skip this index
//!   (mirrors `IdentityStore::by_tenant` Some-only contract)
//! - `by_pair_kind` — duplicate-prevention index. Key:
//!   `"{tenant_or_sentinel}|{from_id}|{to_id}|{kind_discriminant}"`.
//!   Prevents creating a second identical edge in the same tenant.
//!
//! Rebuilt by `Hydra::recover_from_events` via `apply_event`;
//! restored from a snapshot body via direct insertion. Patch 37
//! ships only the create path — no update / delete events yet
//! (those are explicitly deferred; wrong links are corrected by
//! creating a new link with corrected semantics, and the wrong
//! link remains in the audit log forever).
//!
//! ## Uniqueness contract (enforced at create-time)
//!
//! `(tenant, from_entity_id, to_entity_id, kind.discriminant())`
//! must map to AT MOST ONE link. Returns `QueryError` if a
//! second link tries to claim a key already in use. The tenant
//! slot uses the `__system__` sentinel for `None`-tenanted links
//! so that a `None`-tenanted link with coincidentally-identical
//! entity ids cannot collide with a `Some(t)`-tenanted link.
//!
//! ## Validation flow (LOAD-BEARING ordering)
//!
//! `create_link` validates the link AT THE STORE FIRST, then
//! `Hydra::create_identity_link` ingests the
//! `IdentityLinkCreated` event ONLY on store success. On any
//! rejection — self-link, invalid kind, unknown entity, tenant
//! mismatch, duplicate pair+kind — the audit log stays untouched.
//! Mirrors the P29 `create_identity_entity` flow exactly.
//!
//! `apply_event` is the replay path and bypasses validation
//! (the original `create_link` call already validated). Same
//! pattern as `IdentityStore::apply_event`.

use crate::identity_store::IdentityStore;
use hydra_core::{
    error::{HydraError, Result},
    Event, EventKind, IdentityEntityId, IdentityLink, IdentityLinkId,
    IdentityLinkKind, TenantId,
};
use std::collections::{BTreeSet, HashMap};

/// Reserved sentinel for `None`-tenant slots in the `by_pair_kind`
/// index. Same rationale as the alias-key + canonical-key
/// sentinels — internal-only, never accept user input that
/// matches.
const PAIR_KIND_TENANT_NONE_SENTINEL: &str = "__system__";

/// Materialized Identity Graph relationship state. Built from
/// the event log; survives restart via snapshot + replay (same
/// lifecycle as `IdentityStore`, `CausalCellStore`,
/// `MicroModelStore`).
#[derive(Debug, Clone, Default)]
pub struct IdentityLinkStore {
    by_id: HashMap<IdentityLinkId, IdentityLink>,
    by_kind: HashMap<String, BTreeSet<IdentityLinkId>>,
    by_from: HashMap<IdentityEntityId, BTreeSet<IdentityLinkId>>,
    by_to: HashMap<IdentityEntityId, BTreeSet<IdentityLinkId>>,
    /// Some-only — `None`-tenanted links are physically absent
    /// from this index (mirrors `IdentityStore::by_tenant`).
    by_tenant: HashMap<TenantId, BTreeSet<IdentityLinkId>>,
    /// Duplicate-prevention index. Key:
    /// `"{tenant_or_sentinel}|{from_id}|{to_id}|{kind_discriminant}"`.
    by_pair_kind: HashMap<String, IdentityLinkId>,
}

impl IdentityLinkStore {
    pub fn new() -> Self {
        Self::default()
    }

    // === Counts ===

    pub fn link_count(&self) -> usize {
        self.by_id.len()
    }

    // === Direct lookups ===

    pub fn link(&self, id: &IdentityLinkId) -> Option<&IdentityLink> {
        self.by_id.get(id)
    }

    pub fn all_links(&self) -> impl Iterator<Item = &IdentityLink> {
        self.by_id.values()
    }

    // === Indexed lookups ===

    /// All links whose `kind` matches the given variant (via
    /// `IdentityLinkKind::discriminant()`). Returns
    /// `Vec<&IdentityLink>` so callers don't have to chain
    /// `.into_iter()` themselves — matches
    /// `IdentityStore::entities_with_kind`.
    pub fn links_with_kind(
        &self,
        kind: &IdentityLinkKind,
    ) -> Vec<&IdentityLink> {
        let key = kind.discriminant();
        self.by_kind
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    /// All outgoing links from the given entity. Includes links
    /// of every kind; callers can filter further via `kind`.
    pub fn links_from(
        &self,
        from: &IdentityEntityId,
    ) -> Vec<&IdentityLink> {
        self.by_from
            .get(from)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    /// All incoming links to the given entity. Includes links of
    /// every kind; callers can filter further via `kind`.
    pub fn links_to(
        &self,
        to: &IdentityEntityId,
    ) -> Vec<&IdentityLink> {
        self.by_to
            .get(to)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    /// All links touching the given entity in EITHER direction.
    /// Deduplicates internally — a hypothetical self-link (which
    /// `create_link` rejects, but a future relaxation might
    /// allow) would not appear twice.
    pub fn links_for_entity(
        &self,
        entity: &IdentityEntityId,
    ) -> Vec<&IdentityLink> {
        let mut ids: BTreeSet<&IdentityLinkId> = BTreeSet::new();
        if let Some(set) = self.by_from.get(entity) {
            ids.extend(set.iter());
        }
        if let Some(set) = self.by_to.get(entity) {
            ids.extend(set.iter());
        }
        ids.into_iter()
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    /// All links scoped to a given tenant. `None`-tenanted
    /// (system-wide) links are NOT returned — mirrors P29's
    /// `entities_for_tenant` Some-only contract. A caller asking
    /// "for this tenant" wants strict scoping.
    pub fn links_for_tenant(
        &self,
        tenant: &TenantId,
    ) -> Vec<&IdentityLink> {
        self.by_tenant
            .get(tenant)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect()
    }

    // === Create path (with uniqueness + structural checks) ===

    /// Validate-and-insert. Used by `Hydra::create_identity_link`
    /// at the engine boundary. Returns `QueryError` for:
    ///
    /// - duplicate link id (defensive — shouldn't happen for
    ///   ULID-minted ids but rejected anyway)
    /// - invalid `link.kind` (empty `Custom`, sentinel `Custom`,
    ///   built-in-collision `Custom`)
    /// - self-link (`from_entity_id == to_entity_id`)
    /// - unknown `from_entity_id` OR unknown `to_entity_id`
    /// - tenant mismatch — `link.tenant_id`, `from.tenant_id`,
    ///   `to.tenant_id` must all agree (including `None == None`).
    ///   **LOAD-BEARING**: tenant-mismatch surfaces as the SAME
    ///   `"unknown identity entity: {id}"` error as a genuine
    ///   miss, so wrong-tenant probes can't enumerate which ids
    ///   exist under other tenants. Mirrors P32 / P33.
    /// - duplicate pair+kind — `(tenant, from, to,
    ///   kind.discriminant())` already mapped to another link
    pub fn create_link(
        &mut self,
        link: IdentityLink,
        entities: &IdentityStore,
    ) -> Result<IdentityLink> {
        // 1. Defensive: reject duplicate link id.
        if self.by_id.contains_key(&link.id) {
            return Err(HydraError::QueryError(format!(
                "identity link id already exists: {}",
                link.id
            )));
        }

        // 2. Structural validation — self-link rejection +
        //    custom-kind sentinel / collision rejection. Lives on
        //    the type so it can be reused by the wire layer in
        //    P38.
        link.validate().map_err(HydraError::QueryError)?;

        // 3. Load both entities. Wrong-tenant + Some/None
        //    mismatch + genuine miss MUST all return the same
        //    unified error to prevent cross-tenant existence
        //    enumeration. Mirrors P32 (hydra.rs:2627-2637).
        let from_entity = entities.entity(&link.from_entity_id);
        let to_entity = entities.entity(&link.to_entity_id);
        let from_visible = matches!(
            from_entity,
            Some(e) if e.tenant_id == link.tenant_id
        );
        let to_visible = matches!(
            to_entity,
            Some(e) if e.tenant_id == link.tenant_id
        );
        if !from_visible {
            return Err(HydraError::QueryError(format!(
                "unknown identity entity: {}",
                link.from_entity_id
            )));
        }
        if !to_visible {
            return Err(HydraError::QueryError(format!(
                "unknown identity entity: {}",
                link.to_entity_id
            )));
        }

        // 4. Duplicate pair+kind check.
        let pair_key = pair_kind_index_key(
            link.tenant_id.as_ref(),
            &link.from_entity_id,
            &link.to_entity_id,
            &link.kind,
        );
        if let Some(existing) = self.by_pair_kind.get(&pair_key) {
            return Err(HydraError::QueryError(format!(
                "duplicate link (from={}, to={}, kind={}) — \
                 already mapped to link {}",
                link.from_entity_id,
                link.to_entity_id,
                link.kind.discriminant(),
                existing
            )));
        }

        // 5. All checks passed — insert.
        self.insert_link(link.clone());
        Ok(link)
    }

    // === Event ingest ===

    /// Apply one event. Patch 37's only relevant variant is
    /// `IdentityLinkCreated`. Replay does NOT re-run the
    /// uniqueness checks because the original `create_link` call
    /// already validated; replay is meant to be a faithful state
    /// rebuild. Same pattern as `IdentityStore::apply_event`.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        if let EventKind::IdentityLinkCreated { link } = &event.kind {
            self.insert_link(link.clone());
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

    /// Insert a link directly, bypassing uniqueness checks. Used
    /// by `Hydra::recover_from_snapshot_body_and_replay` to seed
    /// the store from a snapshot body's `identity_links` vec
    /// without re-emitting `IdentityLinkCreated` events, and by
    /// `apply_event` during replay. Idempotent on re-insert:
    /// removes prior index entries before installing the new
    /// ones — mirrors `IdentityStore::insert_entity`.
    pub fn insert_link(&mut self, link: IdentityLink) {
        let id = link.id.clone();
        if let Some(existing) = self.by_id.remove(&id) {
            self.remove_indexes(&existing);
        }
        self.add_indexes(&link);
        self.by_id.insert(id, link);
    }

    fn add_indexes(&mut self, link: &IdentityLink) {
        let kind_key = link.kind.discriminant();
        self.by_kind
            .entry(kind_key)
            .or_default()
            .insert(link.id.clone());
        self.by_from
            .entry(link.from_entity_id.clone())
            .or_default()
            .insert(link.id.clone());
        self.by_to
            .entry(link.to_entity_id.clone())
            .or_default()
            .insert(link.id.clone());
        if let Some(tenant) = &link.tenant_id {
            self.by_tenant
                .entry(tenant.clone())
                .or_default()
                .insert(link.id.clone());
        }
        let pair_key = pair_kind_index_key(
            link.tenant_id.as_ref(),
            &link.from_entity_id,
            &link.to_entity_id,
            &link.kind,
        );
        self.by_pair_kind.insert(pair_key, link.id.clone());
    }

    fn remove_indexes(&mut self, link: &IdentityLink) {
        let kind_key = link.kind.discriminant();
        if let Some(set) = self.by_kind.get_mut(&kind_key) {
            set.remove(&link.id);
            if set.is_empty() {
                self.by_kind.remove(&kind_key);
            }
        }
        if let Some(set) = self.by_from.get_mut(&link.from_entity_id) {
            set.remove(&link.id);
            if set.is_empty() {
                self.by_from.remove(&link.from_entity_id);
            }
        }
        if let Some(set) = self.by_to.get_mut(&link.to_entity_id) {
            set.remove(&link.id);
            if set.is_empty() {
                self.by_to.remove(&link.to_entity_id);
            }
        }
        if let Some(tenant) = &link.tenant_id {
            if let Some(set) = self.by_tenant.get_mut(tenant) {
                set.remove(&link.id);
                if set.is_empty() {
                    self.by_tenant.remove(tenant);
                }
            }
        }
        let pair_key = pair_kind_index_key(
            link.tenant_id.as_ref(),
            &link.from_entity_id,
            &link.to_entity_id,
            &link.kind,
        );
        self.by_pair_kind.remove(&pair_key);
    }
}

/// Compose the `by_pair_kind` index key.
///
/// Format: `"{tenant_or_sentinel}|{from_id}|{to_id}|{kind_discriminant}"`.
/// Mirrors the alias-key + canonical-key composition style so all
/// three indexes stay visually parallel.
///
/// The tenant slot is LOAD-BEARING: without it, a `None`-tenanted
/// link with coincidentally-identical entity ids would collide
/// with a `Some(t)`-tenanted link in the index. Same physical-
/// slot separation as `IdentityAlias::index_key` (P29).
fn pair_kind_index_key(
    tenant: Option<&TenantId>,
    from: &IdentityEntityId,
    to: &IdentityEntityId,
    kind: &IdentityLinkKind,
) -> String {
    format!(
        "{}|{}|{}|{}",
        tenant
            .map(|t| t.as_str())
            .unwrap_or(PAIR_KIND_TENANT_NONE_SENTINEL),
        from,
        to,
        kind.discriminant(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hydra_core::{
        ActorId, Confidence, IdentityAlias, IdentityEntity,
        IdentityEntityKind,
    };

    fn make_entity(
        tenant: Option<TenantId>,
        canonical_key: &str,
    ) -> IdentityEntity {
        let now = Utc::now();
        IdentityEntity {
            id: hydra_core::IdentityEntityId::new(),
            tenant_id: tenant,
            kind: IdentityEntityKind::Dataset,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases: vec![IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("analytics".to_string()),
                external_id: Some(canonical_key.to_string()),
                label: canonical_key.to_string(),
                normalized: canonical_key.to_string(),
            }],
            confidence: Confidence::new(0.9),
            metadata: HashMap::new(),
            created_by: ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn make_link(
        tenant: Option<TenantId>,
        kind: IdentityLinkKind,
        from: &IdentityEntityId,
        to: &IdentityEntityId,
    ) -> IdentityLink {
        let now = Utc::now();
        IdentityLink {
            id: IdentityLinkId::new(),
            tenant_id: tenant,
            kind,
            from_entity_id: from.clone(),
            to_entity_id: to.clone(),
            confidence: Confidence::new(0.9),
            evidence_ids: vec![],
            claim_ids: vec![],
            cell_ids: vec![],
            metadata: HashMap::new(),
            created_by: ActorId::from_str("actor_ops"),
            created_at: now,
            caused_by: None,
        }
    }

    fn seed_two_entities(
        store: &mut IdentityStore,
        tenant: Option<TenantId>,
    ) -> (IdentityEntityId, IdentityEntityId) {
        let a = make_entity(tenant.clone(), "dataset/a");
        let b = {
            let mut e = make_entity(tenant.clone(), "dataset/b");
            // Distinct alias so it doesn't collide with `a`'s in
            // the by_alias index (P29 uniqueness).
            e.aliases[0].normalized = "dataset.b".to_string();
            e.aliases[0].label = "dataset.b".to_string();
            e.aliases[0].external_id = Some("dataset.b".to_string());
            e
        };
        let a_id = a.id.clone();
        let b_id = b.id.clone();
        store.create_entity(a).unwrap();
        store.create_entity(b).unwrap();
        (a_id, b_id)
    }

    #[test]
    fn creates_and_reads_link() {
        let mut entities = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let (a, b) = seed_two_entities(&mut entities, Some(tenant.clone()));
        let mut links = IdentityLinkStore::new();
        let link = make_link(
            Some(tenant.clone()),
            IdentityLinkKind::DependsOn,
            &a,
            &b,
        );
        let id = link.id.clone();
        let stored = links.create_link(link, &entities).unwrap();
        assert_eq!(stored.id, id);
        assert_eq!(links.link_count(), 1);
        assert_eq!(links.link(&id).map(|l| &l.id), Some(&id));
    }

    #[test]
    fn indexes_by_kind() {
        let mut entities = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let (a, b) = seed_two_entities(&mut entities, Some(tenant.clone()));
        let mut links = IdentityLinkStore::new();
        links
            .create_link(
                make_link(
                    Some(tenant.clone()),
                    IdentityLinkKind::DependsOn,
                    &a,
                    &b,
                ),
                &entities,
            )
            .unwrap();
        links
            .create_link(
                make_link(
                    Some(tenant),
                    IdentityLinkKind::OwnedBy,
                    &b,
                    &a,
                ),
                &entities,
            )
            .unwrap();
        let depends = links.links_with_kind(&IdentityLinkKind::DependsOn);
        assert_eq!(depends.len(), 1);
        let owned = links.links_with_kind(&IdentityLinkKind::OwnedBy);
        assert_eq!(owned.len(), 1);
        let same_as = links.links_with_kind(&IdentityLinkKind::SameAs);
        assert!(same_as.is_empty());
    }

    #[test]
    fn indexes_by_from_and_by_to() {
        let mut entities = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let (a, b) = seed_two_entities(&mut entities, Some(tenant.clone()));
        let mut links = IdentityLinkStore::new();
        links
            .create_link(
                make_link(
                    Some(tenant),
                    IdentityLinkKind::DependsOn,
                    &a,
                    &b,
                ),
                &entities,
            )
            .unwrap();
        assert_eq!(links.links_from(&a).len(), 1);
        assert_eq!(links.links_to(&b).len(), 1);
        // No outgoing from `b`, no incoming to `a`.
        assert!(links.links_from(&b).is_empty());
        assert!(links.links_to(&a).is_empty());
        // Union surface covers both endpoints.
        assert_eq!(links.links_for_entity(&a).len(), 1);
        assert_eq!(links.links_for_entity(&b).len(), 1);
    }

    #[test]
    fn rejects_self_link() {
        let mut entities = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let (a, _b) = seed_two_entities(&mut entities, Some(tenant.clone()));
        let mut links = IdentityLinkStore::new();
        let bad = make_link(
            Some(tenant),
            IdentityLinkKind::SameAs,
            &a,
            &a,
        );
        let err = links.create_link(bad, &entities).unwrap_err();
        match err {
            HydraError::QueryError(msg) => {
                assert!(
                    msg.contains("self-link rejected"),
                    "expected self-link rejection, got: {msg}"
                );
            }
            other => panic!("expected QueryError, got: {other:?}"),
        }
        assert_eq!(links.link_count(), 0);
    }

    #[test]
    fn rejects_duplicate_pair_kind() {
        let mut entities = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let (a, b) = seed_two_entities(&mut entities, Some(tenant.clone()));
        let mut links = IdentityLinkStore::new();
        links
            .create_link(
                make_link(
                    Some(tenant.clone()),
                    IdentityLinkKind::DependsOn,
                    &a,
                    &b,
                ),
                &entities,
            )
            .unwrap();
        let dup = make_link(
            Some(tenant),
            IdentityLinkKind::DependsOn,
            &a,
            &b,
        );
        let err = links.create_link(dup, &entities).unwrap_err();
        match err {
            HydraError::QueryError(msg) => {
                assert!(msg.contains("duplicate link"), "got: {msg}");
            }
            other => panic!("expected QueryError, got: {other:?}"),
        }
        assert_eq!(links.link_count(), 1);
    }

    #[test]
    fn allows_same_pair_different_kinds() {
        // DependsOn(A,B) and OwnedBy(A,B) are distinct edges —
        // the duplicate-prevention key is per-kind.
        let mut entities = IdentityStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let (a, b) = seed_two_entities(&mut entities, Some(tenant.clone()));
        let mut links = IdentityLinkStore::new();
        links
            .create_link(
                make_link(
                    Some(tenant.clone()),
                    IdentityLinkKind::DependsOn,
                    &a,
                    &b,
                ),
                &entities,
            )
            .unwrap();
        links
            .create_link(
                make_link(
                    Some(tenant),
                    IdentityLinkKind::OwnedBy,
                    &a,
                    &b,
                ),
                &entities,
            )
            .unwrap();
        assert_eq!(links.link_count(), 2);
    }

    #[test]
    fn mixed_tenant_link_rejected_indistinguishably() {
        // LOAD-BEARING. All three failure modes — wrong-tenant
        // entity, Some/None mismatch, and genuine miss — surface
        // as the SAME `"unknown identity entity: {id}"` error.
        // Mirrors P32 indistinguishable-from-missing pattern;
        // prevents cross-tenant existence enumeration.
        let mut entities = IdentityStore::new();
        let tenant_a = TenantId::from_str("tenant_a");
        let tenant_b = TenantId::from_str("tenant_b");
        let (a_in_a, _) =
            seed_two_entities(&mut entities, Some(tenant_a.clone()));

        // Direction 1: link in tenant_b references entity in
        // tenant_a — wrong tenant on the `from` side.
        let mut links = IdentityLinkStore::new();
        let phantom_to = hydra_core::IdentityEntityId::new();
        let cross = make_link(
            Some(tenant_b.clone()),
            IdentityLinkKind::DependsOn,
            &a_in_a,
            &phantom_to,
        );
        let err = links.create_link(cross, &entities).unwrap_err();
        match err {
            HydraError::QueryError(msg) => {
                assert!(
                    msg.contains("unknown identity entity"),
                    "wrong-tenant must surface as unknown identity \
                     entity (no cross-tenant leak), got: {msg}"
                );
            }
            other => panic!("expected QueryError, got: {other:?}"),
        }

        // Direction 2: Some/None mismatch — link.tenant_id is
        // None but entity is in tenant_a. Same indistinguishable
        // error.
        let phantom_to_2 = hydra_core::IdentityEntityId::new();
        let cross2 = make_link(
            None,
            IdentityLinkKind::DependsOn,
            &a_in_a,
            &phantom_to_2,
        );
        let err2 = links.create_link(cross2, &entities).unwrap_err();
        match err2 {
            HydraError::QueryError(msg) => {
                assert!(msg.contains("unknown identity entity"));
            }
            other => panic!("expected QueryError, got: {other:?}"),
        }

        // Direction 3: genuine miss — entity id never created.
        // Same error string.
        let ghost = hydra_core::IdentityEntityId::new();
        let phantom_to_3 = hydra_core::IdentityEntityId::new();
        let cross3 = make_link(
            Some(tenant_a),
            IdentityLinkKind::DependsOn,
            &ghost,
            &phantom_to_3,
        );
        let err3 = links.create_link(cross3, &entities).unwrap_err();
        match err3 {
            HydraError::QueryError(msg) => {
                assert!(msg.contains("unknown identity entity"));
            }
            other => panic!("expected QueryError, got: {other:?}"),
        }

        assert_eq!(links.link_count(), 0);
    }

    #[test]
    fn none_tenanted_link_between_none_entities_allowed() {
        // None + None + None is a valid configuration for
        // system-wide assertions about None-tenanted entities.
        let mut entities = IdentityStore::new();
        let (a, b) = seed_two_entities(&mut entities, None);
        let mut links = IdentityLinkStore::new();
        let link = make_link(
            None,
            IdentityLinkKind::SameAs,
            &a,
            &b,
        );
        let stored = links.create_link(link, &entities).unwrap();
        assert!(stored.tenant_id.is_none());
        // by_tenant index stays empty for None-tenanted links.
        assert!(links.by_tenant.is_empty());
    }

    #[test]
    fn apply_event_replays_link() {
        // Replay path skips validation; inserts directly. Used
        // by `Hydra::recover_from_events` to rebuild the store.
        let mut links = IdentityLinkStore::new();
        let tenant = TenantId::from_str("tenant_p37");
        let a = hydra_core::IdentityEntityId::new();
        let b = hydra_core::IdentityEntityId::new();
        let link = make_link(
            Some(tenant),
            IdentityLinkKind::DependsOn,
            &a,
            &b,
        );
        let event = Event::trigger(EventKind::IdentityLinkCreated {
            link: link.clone(),
        });
        links.apply_event(&event).unwrap();
        assert_eq!(links.link_count(), 1);
        assert!(links.link(&link.id).is_some());
    }
}
