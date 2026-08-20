//! Role and overwrite management: the commands that change who may do what.
//!
//! Every mutation follows the message store's order — written to the database
//! first, then swapped into memory, then announced — so nothing clients are
//! told can vanish on restart. Resolution reads inputs per check, so a
//! mutation takes effect on the very next message or datagram; the broadcasts
//! exist for interfaces, not for enforcement.
//!
//! Two rules gate every edit beyond the `MANAGE_ROLES` bit. Hierarchy: a role
//! at or above your top position is out of reach, so equals cannot strip each
//! other. The bits-subset rule: you may only grant or toggle permissions you
//! yourself hold, unless you are the owner or an administrator — nobody mints
//! powers they do not have.

use crate::state::{PermState, Shared};
use pickle_identity::Fingerprint;
use pickle_proto::{
    can_manage_role, resolve, ChannelId, ClientId, ErrorCode, Overwrite, OverwriteTarget,
    Permissions, Role, RoleId, ServerControl, EVERYONE_ROLE_ID,
};
use std::sync::Arc;

fn ack(shared: &Shared, actor: ClientId, nonce: u64) {
    shared.send(actor, ServerControl::Ack { nonce });
}

fn refuse(shared: &Shared, actor: ClientId, nonce: u64, code: ErrorCode, detail: &str) {
    shared.send(
        actor,
        ServerControl::CommandFailed {
            nonce,
            code,
            detail: detail.into(),
        },
    );
}

/// The actor's standing, resolved once per command: their base bits, their
/// grants, and whether the subset rule applies to them at all.
struct Actor {
    roles: Vec<RoleId>,
    owner: bool,
    base: Permissions,
}

impl Actor {
    /// May this actor hand out these bits? Owner and administrators may mint
    /// anything; everyone else only what they hold.
    fn may_grant(&self, bits: Permissions) -> bool {
        self.owner || self.base.contains(Permissions::ADMINISTRATOR) || self.base.contains(bits)
    }
}

fn actor(shared: &Shared, client: ClientId, nonce: u64) -> Option<Actor> {
    if !shared.can_globally(client, Permissions::MANAGE_ROLES) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NotPermitted,
            "you may not manage roles",
        );
        return None;
    }
    let snapshot = shared.perm_state();
    let fingerprint = shared.fingerprint_of(client)?;
    let roles = snapshot
        .members
        .get(&fingerprint)
        .cloned()
        .unwrap_or_default();
    let owner = shared.is_owner(fingerprint);
    let base = resolve(&snapshot.roles, &roles, fingerprint, owner, None);
    Some(Actor { roles, owner, base })
}

/// Positions after inserting a new role just above @everyone: everything at
/// position 1 and up shifts by one. Returns the full new ordering.
fn shifted_positions(roles: &[Role]) -> Vec<(RoleId, u32)> {
    roles
        .iter()
        .map(|r| {
            if r.position == 0 {
                (r.id, 0)
            } else {
                (r.id, r.position + 1)
            }
        })
        .collect()
}

pub async fn create_role(
    shared: &Arc<Shared>,
    client: ClientId,
    nonce: u64,
    name: String,
    permissions: Permissions,
) {
    let Some(actor) = actor(shared, client, nonce) else {
        return;
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Malformed,
            "a role needs a name",
        );
        return;
    }
    let permissions = permissions.intersect(Permissions::ALL);
    if !actor.may_grant(permissions) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NotPermitted,
            "you cannot grant permissions you do not hold",
        );
        return;
    }
    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };

    let snapshot = shared.perm_state();
    let id = snapshot.roles.iter().map(|r| r.id).max().unwrap_or(0) + 1;
    let positions = shifted_positions(&snapshot.roles);
    let role = Role {
        id,
        name,
        color: None,
        // Just above @everyone, Discord-style: a new role starts junior.
        position: 1,
        permissions,
    };

    if let Err(error) = store.set_role_positions(&positions).await {
        tracing::warn!(%error, "could not shift role positions");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the role was not saved",
        );
        return;
    }
    if let Err(error) = store.insert_role(&role).await {
        tracing::warn!(%error, "could not store a role");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the role was not saved",
        );
        return;
    }

    let mut next = PermState {
        roles: snapshot.roles.clone(),
        members: snapshot.members.clone(),
    };
    for role_entry in &mut next.roles {
        if let Some((_, position)) = positions.iter().find(|(id, _)| *id == role_entry.id) {
            role_entry.position = *position;
        }
    }
    next.roles.push(role.clone());
    next.roles.sort_by_key(|r| r.position);
    let ordering: Vec<(RoleId, u32)> = next.roles.iter().map(|r| (r.id, r.position)).collect();
    shared.swap_perm_state(next);

    shared.broadcast(ServerControl::RoleCreated(role), None);
    shared.broadcast(
        ServerControl::RolesReordered {
            positions: ordering,
        },
        None,
    );
    ack(shared, client, nonce);
}

pub async fn update_role(
    shared: &Arc<Shared>,
    client: ClientId,
    nonce: u64,
    id: RoleId,
    name: Option<String>,
    color: Option<Option<u32>>,
    permissions: Option<Permissions>,
) {
    let Some(actor) = actor(shared, client, nonce) else {
        return;
    };
    let snapshot = shared.perm_state();
    let Some(existing) = snapshot.roles.iter().find(|r| r.id == id) else {
        refuse(shared, client, nonce, ErrorCode::Malformed, "no such role");
        return;
    };
    if !can_manage_role(&snapshot.roles, &actor.roles, actor.owner, id) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NotPermitted,
            "that role is not below yours",
        );
        return;
    }
    if id == EVERYONE_ROLE_ID && name.is_some() {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Malformed,
            "everyone is not renamable",
        );
        return;
    }
    let mut updated = existing.clone();
    if let Some(name) = name {
        let name = name.trim().to_string();
        if name.is_empty() {
            refuse(
                shared,
                client,
                nonce,
                ErrorCode::Malformed,
                "a role needs a name",
            );
            return;
        }
        updated.name = name;
    }
    if let Some(color) = color {
        updated.color = color;
    }
    if let Some(permissions) = permissions {
        let permissions = permissions.intersect(Permissions::ALL);
        // The subset rule applies to what this edit adds, not what the role
        // already had: taking bits away needs no standing to grant them.
        let added = permissions.without(existing.permissions);
        if !actor.may_grant(added) {
            refuse(
                shared,
                client,
                nonce,
                ErrorCode::NotPermitted,
                "you cannot grant permissions you do not hold",
            );
            return;
        }
        updated.permissions = permissions;
    }

    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };
    let before = shared.visible_ids_by_client();
    if let Err(error) = store.update_role(&updated).await {
        tracing::warn!(%error, "could not update a role");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the change was not saved",
        );
        return;
    }

    let mut next = PermState {
        roles: snapshot.roles.clone(),
        members: snapshot.members.clone(),
    };
    if let Some(slot) = next.roles.iter_mut().find(|r| r.id == id) {
        *slot = updated.clone();
    }
    shared.swap_perm_state(next);

    shared.broadcast(ServerControl::RoleUpdated(updated), None);
    // Bits may have flipped visibility for holders; contents of channels did
    // not change, so nothing is "touched".
    shared.resync_visibility(&before, &[]);
    ack(shared, client, nonce);
}

pub async fn delete_role(shared: &Arc<Shared>, client: ClientId, nonce: u64, id: RoleId) {
    let Some(actor) = actor(shared, client, nonce) else {
        return;
    };
    if id == EVERYONE_ROLE_ID {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NotPermitted,
            "everyone is not deletable",
        );
        return;
    }
    let snapshot = shared.perm_state();
    if !snapshot.roles.iter().any(|r| r.id == id) {
        refuse(shared, client, nonce, ErrorCode::Malformed, "no such role");
        return;
    }
    if !can_manage_role(&snapshot.roles, &actor.roles, actor.owner, id) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NotPermitted,
            "that role is not below yours",
        );
        return;
    }
    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };

    let before = shared.visible_ids_by_client();
    if let Err(error) = store.delete_role(id).await {
        tracing::warn!(%error, "could not delete a role");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the deletion was not saved",
        );
        return;
    }

    // Memory follows the store's cascade: the role, its grants, its
    // overwrites, and compacted positions.
    let mut next = PermState {
        roles: snapshot
            .roles
            .iter()
            .filter(|r| r.id != id)
            .cloned()
            .collect(),
        members: snapshot
            .members
            .iter()
            .map(|(fp, roles)| {
                (
                    *fp,
                    roles
                        .iter()
                        .copied()
                        .filter(|r| *r != id)
                        .collect::<Vec<_>>(),
                )
            })
            .collect(),
    };
    next.roles.sort_by_key(|r| r.position);
    for (index, role) in next.roles.iter_mut().enumerate() {
        role.position = index as u32;
    }
    let ordering: Vec<(RoleId, u32)> = next.roles.iter().map(|r| (r.id, r.position)).collect();
    if let Err(error) = store.set_role_positions(&ordering).await {
        tracing::warn!(%error, "could not compact role positions");
    }
    shared.swap_perm_state(next);

    let touched = shared.strip_role_overwrites(id);
    let holders = shared.strip_live_role(id);

    shared.broadcast(ServerControl::RoleDeleted { id }, None);
    shared.broadcast(
        ServerControl::RolesReordered {
            positions: ordering,
        },
        None,
    );
    for info in holders {
        shared.broadcast(ServerControl::UserUpdated(Box::new(info)), None);
    }
    shared.resync_visibility(&before, &touched);
    ack(shared, client, nonce);
}

pub async fn reorder_roles(
    shared: &Arc<Shared>,
    client: ClientId,
    nonce: u64,
    positions: Vec<(RoleId, u32)>,
) {
    let Some(actor) = actor(shared, client, nonce) else {
        return;
    };
    let snapshot = shared.perm_state();

    // A dense permutation of every role, @everyone pinned at zero.
    let mut expected: Vec<u32> = (0..snapshot.roles.len() as u32).collect();
    let mut given: Vec<u32> = positions.iter().map(|(_, p)| *p).collect();
    given.sort_unstable();
    let names_all = positions.len() == snapshot.roles.len()
        && snapshot
            .roles
            .iter()
            .all(|r| positions.iter().any(|(id, _)| *id == r.id));
    expected.dedup();
    if !names_all || given != expected {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Malformed,
            "a reorder names every role exactly once, densely",
        );
        return;
    }
    if positions
        .iter()
        .any(|(id, p)| *id == EVERYONE_ROLE_ID && *p != 0)
    {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Malformed,
            "everyone stays at the bottom",
        );
        return;
    }
    if !actor.owner {
        let my_top = pickle_proto::top_role_position(&snapshot.roles, &actor.roles);
        for (id, new_position) in &positions {
            let old = snapshot
                .roles
                .iter()
                .find(|r| r.id == *id)
                .map(|r| r.position)
                .unwrap_or(0);
            let moved = old != *new_position;
            if moved && (old >= my_top || *new_position >= my_top) {
                refuse(
                    shared,
                    client,
                    nonce,
                    ErrorCode::NotPermitted,
                    "you can only move roles below your own",
                );
                return;
            }
        }
    }

    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };
    if let Err(error) = store.set_role_positions(&positions).await {
        tracing::warn!(%error, "could not store the reorder");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the reorder was not saved",
        );
        return;
    }

    let mut next = PermState {
        roles: snapshot.roles.clone(),
        members: snapshot.members.clone(),
    };
    for role in &mut next.roles {
        if let Some((_, p)) = positions.iter().find(|(id, _)| *id == role.id) {
            role.position = *p;
        }
    }
    next.roles.sort_by_key(|r| r.position);
    shared.swap_perm_state(next);

    shared.broadcast(ServerControl::RolesReordered { positions }, None);
    ack(shared, client, nonce);
}

pub async fn set_member_roles(
    shared: &Arc<Shared>,
    client: ClientId,
    nonce: u64,
    fingerprint: Fingerprint,
    roles: Vec<RoleId>,
) {
    let Some(actor) = actor(shared, client, nonce) else {
        return;
    };
    let snapshot = shared.perm_state();
    if roles.contains(&EVERYONE_ROLE_ID) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Malformed,
            "everyone is implicit, not granted",
        );
        return;
    }
    if roles
        .iter()
        .any(|id| !snapshot.roles.iter().any(|r| r.id == *id))
    {
        refuse(shared, client, nonce, ErrorCode::Malformed, "no such role");
        return;
    }
    if shared.is_owner(fingerprint) && !actor.owner {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NotPermitted,
            "the owner's roles are not yours to change",
        );
        return;
    }
    // Hierarchy on the diff: every role added or removed must be strictly
    // below the actor's top. Senior roles the member already holds are
    // untouchable — and therefore also unremovable — by a junior actor.
    let current = snapshot
        .members
        .get(&fingerprint)
        .cloned()
        .unwrap_or_default();
    let changed: Vec<RoleId> = current
        .iter()
        .filter(|r| !roles.contains(r))
        .chain(roles.iter().filter(|r| !current.contains(r)))
        .copied()
        .collect();
    for role in &changed {
        if !can_manage_role(&snapshot.roles, &actor.roles, actor.owner, *role) {
            refuse(
                shared,
                client,
                nonce,
                ErrorCode::NotPermitted,
                "some of those roles are not below yours",
            );
            return;
        }
    }

    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };
    let before = shared.visible_ids_by_client();
    if let Err(error) = store.replace_member_roles(fingerprint, &roles).await {
        tracing::warn!(%error, "could not store the role grants");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the change was not saved",
        );
        return;
    }

    let mut next = PermState {
        roles: snapshot.roles.clone(),
        members: snapshot.members.clone(),
    };
    if roles.is_empty() {
        next.members.remove(&fingerprint);
    } else {
        next.members.insert(fingerprint, roles.clone());
    }
    shared.swap_perm_state(next);

    for info in shared.update_live_member_roles(fingerprint, &roles) {
        shared.broadcast(ServerControl::UserUpdated(Box::new(info)), None);
    }
    shared.resync_visibility(&before, &[]);
    ack(shared, client, nonce);
}

pub async fn set_channel_overwrite(
    shared: &Arc<Shared>,
    client: ClientId,
    nonce: u64,
    channel: ChannelId,
    target: OverwriteTarget,
    allow: Permissions,
    deny: Permissions,
) {
    let Some(actor) = actor(shared, client, nonce) else {
        return;
    };
    // Configuring a room you cannot see answers as if it does not exist.
    if !shared.can(client, channel, Permissions::VIEW_CHANNEL) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NoSuchChannel,
            "no such channel",
        );
        return;
    }
    let allow = allow.intersect(Permissions::CHANNEL_SCOPED);
    let deny = deny.intersect(Permissions::CHANNEL_SCOPED);
    if !allow.intersect(deny).is_empty() {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Malformed,
            "a bit cannot be both allowed and denied",
        );
        return;
    }
    if let OverwriteTarget::Role(role) = target {
        let snapshot = shared.perm_state();
        if !snapshot.roles.iter().any(|r| r.id == role) {
            refuse(shared, client, nonce, ErrorCode::Malformed, "no such role");
            return;
        }
    }
    // The channel-scoped subset rule: you may only toggle, in this channel,
    // permissions you yourself hold in it.
    if !actor.owner && !actor.base.contains(Permissions::ADMINISTRATOR) {
        let snapshot = shared.perm_state();
        let Some(fingerprint) = shared.fingerprint_of(client) else {
            return; // the actor vanished mid-command; nobody to answer
        };
        let mine = {
            let channels = shared.channels();
            let Some(target_channel) = channels.iter().find(|c| c.id == channel) else {
                refuse(
                    shared,
                    client,
                    nonce,
                    ErrorCode::NoSuchChannel,
                    "no such channel",
                );
                return;
            };
            resolve(
                &snapshot.roles,
                &actor.roles,
                fingerprint,
                actor.owner,
                Some(&target_channel.overwrites),
            )
        };
        if !mine.contains(allow.union(deny)) {
            refuse(
                shared,
                client,
                nonce,
                ErrorCode::NotPermitted,
                "you cannot toggle permissions you do not hold here",
            );
            return;
        }
    }

    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };
    let overwrite = Overwrite {
        target,
        allow,
        deny,
    };
    let before = shared.visible_ids_by_client();
    if let Err(error) = store.upsert_overwrite(channel, &overwrite).await {
        tracing::warn!(%error, "could not store an overwrite");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the change was not saved",
        );
        return;
    }
    shared.set_channel_overwrite(channel, overwrite);
    shared.resync_visibility(&before, &[channel]);
    ack(shared, client, nonce);
}

pub async fn delete_channel_overwrite(
    shared: &Arc<Shared>,
    client: ClientId,
    nonce: u64,
    channel: ChannelId,
    target: OverwriteTarget,
) {
    let Some(_actor) = actor(shared, client, nonce) else {
        return;
    };
    if !shared.can(client, channel, Permissions::VIEW_CHANNEL) {
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::NoSuchChannel,
            "no such channel",
        );
        return;
    }
    let Some(store) = shared.store() else {
        refuse(shared, client, nonce, ErrorCode::Internal, "no database");
        return;
    };
    let before = shared.visible_ids_by_client();
    if let Err(error) = store.delete_overwrite(channel, &target).await {
        tracing::warn!(%error, "could not delete an overwrite");
        refuse(
            shared,
            client,
            nonce,
            ErrorCode::Internal,
            "the change was not saved",
        );
        return;
    }
    // Idempotent: deleting what is not there is success, not an error.
    shared.remove_channel_overwrite(channel, &target);
    shared.resync_visibility(&before, &[channel]);
    ack(shared, client, nonce);
}
