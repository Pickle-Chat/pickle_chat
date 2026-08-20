//! The moderation commands: authority over other members.
//!
//! Every handler runs the same ladder — the permission bit, then hierarchy,
//! then the effect — and answers the actor by nonce: `Ack` on success,
//! `CommandFailed` on refusal, so an admin UI gets positive, correlated
//! completion instead of inferring from broadcasts.
//!
//! Hierarchy is rank alone and is checked against fingerprints, not client
//! ids, so an offline admin is exactly as protected as an online one and the
//! owner can never be acted on, present or not.

use crate::state::Shared;
use pickle_identity::Fingerprint;
use pickle_proto::{
    BanEntry, ChannelId, ClientId, DisconnectReason, ErrorCode, Permissions, ServerControl,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// QUIC application close codes, continuing the session module's 0..=2.
const CLOSE_KICKED: u32 = 3;
const CLOSE_BANNED: u32 = 4;

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

/// The shared front half: the bit, the target's existence, and hierarchy.
/// Returns the target's fingerprint so the effect half can use it.
fn authorize_against_online(
    shared: &Shared,
    actor: ClientId,
    nonce: u64,
    bit: Permissions,
    target: ClientId,
) -> Option<Fingerprint> {
    if !shared.can_globally(actor, bit) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "you may not do that",
        );
        return None;
    }
    let Some(fingerprint) = shared.fingerprint_of(target) else {
        refuse(shared, actor, nonce, ErrorCode::Malformed, "no such client");
        return None;
    };
    if !shared.actor_outranks(actor, fingerprint) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "their highest role is not below yours",
        );
        return None;
    }
    Some(fingerprint)
}

/// Eject, give the UserLeft frame its 50 ms to flush (the handshake-refusal
/// precedent), then close the transport authoritatively.
async fn eject_and_close(shared: &Arc<Shared>, victim: ClientId, reason: DisconnectReason) {
    let Some(entry) = shared.eject(victim, reason) else {
        return;
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (code, text): (u32, &[u8]) = match reason {
        DisconnectReason::Banned => (CLOSE_BANNED, b"banned"),
        _ => (CLOSE_KICKED, b"kicked"),
    };
    entry.close_transport(code, text);
}

pub async fn kick(
    shared: &Arc<Shared>,
    actor: ClientId,
    nonce: u64,
    target: ClientId,
    reason: String,
) {
    let Some(fingerprint) =
        authorize_against_online(shared, actor, nonce, Permissions::KICK_MEMBERS, target)
    else {
        return;
    };
    info!(%fingerprint, actor, reason, "kicking");
    // Kicks are not persistent — no store write, deliberately.
    eject_and_close(shared, target, DisconnectReason::Kicked).await;
    ack(shared, actor, nonce);
}

pub async fn ban(
    shared: &Arc<Shared>,
    actor: ClientId,
    nonce: u64,
    fingerprint: Fingerprint,
    reason: String,
    until_unix_ms: Option<u64>,
) {
    if !shared.can_globally(actor, Permissions::BAN_MEMBERS) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "you may not do that",
        );
        return;
    }
    // Hierarchy against the fingerprint, so offline targets are covered and
    // the owner is unbannable. Equal rank blocks self-bans for everyone but
    // the owner, who gets the explicit guard.
    if Some(fingerprint) == shared.fingerprint_of(actor) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "you cannot ban yourself",
        );
        return;
    }
    if !shared.actor_outranks(actor, fingerprint) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "their highest role is not below yours",
        );
        return;
    }
    let Some(store) = shared.store() else {
        refuse(shared, actor, nonce, ErrorCode::Internal, "no database");
        return;
    };
    let issued_by = shared.fingerprint_of(actor).unwrap_or(fingerprint);
    let entry = BanEntry {
        fingerprint,
        reason,
        until_unix_ms,
        issued_by,
        issued_at_unix_ms: crate::state::now_unix_ms(),
    };
    // Stored before enforced, the same order messages follow: a ban everyone
    // watched happen must not vanish on restart.
    if let Err(error) = store.insert_ban(&entry).await {
        warn!(%error, "could not store a ban");
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::Internal,
            "the ban was not saved",
        );
        return;
    }
    info!(%fingerprint, actor, "banned");
    // Every live session of that fingerprint goes, not just one.
    let victims: Vec<ClientId> = shared
        .users()
        .into_iter()
        .filter(|u| u.fingerprint() == fingerprint)
        .map(|u| u.client_id)
        .collect();
    for victim in victims {
        eject_and_close(shared, victim, DisconnectReason::Banned).await;
    }
    ack(shared, actor, nonce);
}

pub async fn unban(shared: &Arc<Shared>, actor: ClientId, nonce: u64, fingerprint: Fingerprint) {
    if !shared.can_globally(actor, Permissions::BAN_MEMBERS) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "you may not do that",
        );
        return;
    }
    // No hierarchy: unbanning threatens nobody.
    let Some(store) = shared.store() else {
        refuse(shared, actor, nonce, ErrorCode::Internal, "no database");
        return;
    };
    if let Err(error) = store.delete_ban(fingerprint).await {
        warn!(%error, "could not delete a ban");
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::Internal,
            "the unban was not saved",
        );
        return;
    }
    ack(shared, actor, nonce);
}

pub async fn list_bans(shared: &Arc<Shared>, actor: ClientId, nonce: u64) {
    if !shared.can_globally(actor, Permissions::BAN_MEMBERS) {
        refuse(
            shared,
            actor,
            nonce,
            ErrorCode::NotPermitted,
            "you may not do that",
        );
        return;
    }
    let Some(store) = shared.store() else {
        refuse(shared, actor, nonce, ErrorCode::Internal, "no database");
        return;
    };
    match store.list_bans().await {
        // The list is the reply; no Ack rides alongside it.
        Ok(bans) => shared.send(actor, ServerControl::BanList { bans }),
        Err(error) => {
            warn!(%error, "could not list bans");
            refuse(
                shared,
                actor,
                nonce,
                ErrorCode::Internal,
                "could not read the ban list",
            );
        }
    }
}

pub fn set_server_mute(
    shared: &Arc<Shared>,
    actor: ClientId,
    nonce: u64,
    target: ClientId,
    muted: bool,
) {
    if authorize_against_online(shared, actor, nonce, Permissions::MUTE_MEMBERS, target).is_none() {
        return;
    }
    let Some(info) = shared.set_server_muted(target, muted) else {
        refuse(shared, actor, nonce, ErrorCode::Malformed, "no such client");
        return;
    };
    // Session-only, deliberately: Discord persists server mutes across
    // reconnects, this build does not yet — a member_flags table can add it.
    shared.broadcast(ServerControl::UserUpdated(Box::new(info)), None);
    ack(shared, actor, nonce);
}

pub fn move_member(
    shared: &Arc<Shared>,
    actor: ClientId,
    nonce: u64,
    target: ClientId,
    to: Option<ChannelId>,
) {
    if authorize_against_online(shared, actor, nonce, Permissions::MOVE_MEMBERS, target).is_none() {
        return;
    }
    // Discord's rule: you may only move people into rooms you could enter
    // yourself — the mover's VIEW and CONNECT; the target's are deliberately
    // bypassed. Capacity still applies: movers do not fill rooms past their
    // cap.
    if let Some(channel) = to {
        if !shared.can(actor, channel, Permissions::VIEW_CHANNEL) {
            refuse(
                shared,
                actor,
                nonce,
                ErrorCode::NoSuchChannel,
                "no such channel",
            );
            return;
        }
        if !shared.can(actor, channel, Permissions::CONNECT) {
            refuse(
                shared,
                actor,
                nonce,
                ErrorCode::NotPermitted,
                "you cannot enter that channel yourself",
            );
            return;
        }
    }
    match shared.force_move(target, to) {
        Ok(from) => {
            shared.broadcast(
                ServerControl::UserMoved {
                    client: target,
                    from,
                    to,
                },
                None,
            );
            ack(shared, actor, nonce);
        }
        Err(code) => refuse(shared, actor, nonce, code, "could not move them"),
    }
}
