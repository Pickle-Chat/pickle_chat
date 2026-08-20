//! The client's view of its own permissions.
//!
//! A per-session mirror of the permission inputs — the role table, this
//! member's grants, and every visible channel with its overwrites — resolved
//! through the same [`pickle_proto::resolve`] the server enforces with. One
//! implementation of the rules on both ends is what makes the controls this
//! app disables and the actions the server refuses provably the same thing.
//!
//! The mirror is rendering state, nothing more. The server re-resolves every
//! action; nothing computed here is trusted, and nothing here is a check.

use pickle_client::{ClientEvent, SessionInfo};
use pickle_identity::Fingerprint;
use pickle_proto::{resolve, Channel, ChannelId, Permissions, Role, RoleId};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The mirror as it is shared: the pump writes, commands read. The critical
/// sections are map updates and bit math — the same never-await-under-a-lock
/// discipline the server keeps.
pub type SessionPerms = Arc<parking_lot::Mutex<PermMirror>>;

/// What this member may do, resolved per channel, in the shape the frontend
/// consumes. Booleans rather than bit names: TypeScript renders decisions, it
/// does not make them.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MyPermissionsDto {
    pub is_owner: bool,
    /// Administrator in the base — everything, everywhere.
    pub is_admin: bool,
    pub channels: BTreeMap<ChannelId, ChannelPermissionsDto>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelPermissionsDto {
    pub send: bool,
    pub read_history: bool,
    pub connect: bool,
    pub speak: bool,
}

/// The per-session mirror. Folded forward by the event pump; read by the
/// commands that seed the frontend.
pub struct PermMirror {
    fingerprint: Fingerprint,
    owner: bool,
    roles: Vec<Role>,
    my_roles: Vec<RoleId>,
    channels: BTreeMap<ChannelId, Channel>,
    /// Everyone connected, for hierarchy answers: may I act on *them*?
    users: std::collections::HashMap<pickle_proto::ClientId, MemberStanding>,
}

/// What hierarchy needs to know about another member.
struct MemberStanding {
    fingerprint: Fingerprint,
    roles: Vec<RoleId>,
    owner: bool,
}

/// The context menu's answer: which actions to offer against one member, and
/// why not, when not.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ModerationOptionsDto {
    pub can_kick: bool,
    pub can_ban: bool,
    pub can_mute: bool,
    pub can_move: bool,
    /// Set when everything above is false — one honest sentence for the
    /// disabled menu, e.g. "Their highest role is not below yours."
    pub reason: Option<String>,
}

impl PermMirror {
    pub fn from_session(fingerprint: Fingerprint, info: &SessionInfo) -> Self {
        let me = info.users.iter().find(|u| u.client_id == info.client_id);
        Self {
            fingerprint,
            owner: me.map(|u| u.owner).unwrap_or(false),
            my_roles: me.map(|u| u.roles.clone()).unwrap_or_default(),
            roles: info.roles.clone(),
            channels: info.channels.iter().map(|c| (c.id, c.clone())).collect(),
            users: info
                .users
                .iter()
                .map(|u| {
                    (
                        u.client_id,
                        MemberStanding {
                            fingerprint: u.fingerprint(),
                            roles: u.roles.clone(),
                            owner: u.owner,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Fold one event in. Returns `true` when the answer to "what may I do"
    /// could have changed, which is the pump's cue to re-emit the snapshot.
    pub fn apply(&mut self, event: &ClientEvent) -> bool {
        match event {
            ClientEvent::ChannelCreated(channel) | ClientEvent::ChannelUpdated(channel) => {
                self.channels.insert(channel.id, channel.clone());
                true
            }
            ClientEvent::ChannelRemoved(id) => {
                self.channels.remove(id);
                true
            }
            ClientEvent::RoleCreated(role) | ClientEvent::RoleUpdated(role) => {
                self.roles.retain(|r| r.id != role.id);
                self.roles.push(role.clone());
                self.roles.sort_by_key(|r| r.position);
                true
            }
            ClientEvent::RoleDeleted { id } => {
                self.roles.retain(|r| r.id != *id);
                self.my_roles.retain(|r| r != id);
                true
            }
            ClientEvent::RolesReordered { positions } => {
                for (id, position) in positions {
                    if let Some(role) = self.roles.iter_mut().find(|r| r.id == *id) {
                        role.position = *position;
                    }
                }
                self.roles.sort_by_key(|r| r.position);
                true
            }
            ClientEvent::UserJoined(user) | ClientEvent::UserUpdated(user) => {
                self.users.insert(
                    user.client_id,
                    MemberStanding {
                        fingerprint: user.fingerprint(),
                        roles: user.roles.clone(),
                        owner: user.owner,
                    },
                );
                // Our own grants arrive the same way; only they change what
                // the interface should enable.
                if user.fingerprint() == self.fingerprint {
                    let changed = user.roles != self.my_roles || user.owner != self.owner;
                    self.my_roles = user.roles.clone();
                    self.owner = user.owner;
                    changed
                } else {
                    false
                }
            }
            ClientEvent::UserLeft { client, .. } => {
                self.users.remove(client);
                false
            }
            _ => false,
        }
    }

    /// The full snapshot the frontend keeps.
    pub fn my_permissions(&self) -> MyPermissionsDto {
        let base = resolve(
            &self.roles,
            &self.my_roles,
            self.fingerprint,
            self.owner,
            None,
        );
        MyPermissionsDto {
            is_owner: self.owner,
            is_admin: base.contains(Permissions::ADMINISTRATOR),
            channels: self
                .channels
                .values()
                .map(|channel| {
                    let bits = resolve(
                        &self.roles,
                        &self.my_roles,
                        self.fingerprint,
                        self.owner,
                        Some(&channel.overwrites),
                    );
                    (
                        channel.id,
                        ChannelPermissionsDto {
                            send: bits.contains(Permissions::SEND_MESSAGES),
                            read_history: bits.contains(Permissions::READ_HISTORY),
                            connect: bits.contains(Permissions::CONNECT),
                            speak: bits.contains(Permissions::SPEAK),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Which moderation actions to offer against one member. Rendering state:
    /// the server re-checks every action regardless.
    pub fn moderation_options(&self, target: pickle_proto::ClientId) -> ModerationOptionsDto {
        let none = |reason: &str| ModerationOptionsDto {
            can_kick: false,
            can_ban: false,
            can_mute: false,
            can_move: false,
            reason: Some(reason.into()),
        };
        let Some(them) = self.users.get(&target) else {
            return none("They are no longer connected.");
        };
        if them.fingerprint == self.fingerprint {
            return none("That would be you.");
        }
        let outranked = pickle_proto::can_act_on(
            &self.roles,
            &self.my_roles,
            self.owner,
            &them.roles,
            them.owner,
        );
        if !outranked {
            return none(if them.owner {
                "They own this server."
            } else {
                "Their highest role is not below yours."
            });
        }
        let base = resolve(
            &self.roles,
            &self.my_roles,
            self.fingerprint,
            self.owner,
            None,
        );
        let options = ModerationOptionsDto {
            can_kick: base.contains(Permissions::KICK_MEMBERS),
            can_ban: base.contains(Permissions::BAN_MEMBERS),
            can_mute: base.contains(Permissions::MUTE_MEMBERS),
            can_move: base.contains(Permissions::MOVE_MEMBERS),
            reason: None,
        };
        if !(options.can_kick || options.can_ban || options.can_mute || options.can_move) {
            return none("You have no moderation permissions here.");
        }
        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;
    use pickle_proto::{ChannelKind, Overwrite, OverwriteTarget, ServerLimits, UserInfo};

    fn channel(id: ChannelId, overwrites: Vec<Overwrite>) -> Channel {
        Channel {
            id,
            parent: None,
            name: format!("channel-{id}"),
            topic: String::new(),
            kind: ChannelKind::VoiceAndText,
            max_users: None,
            order: id as i32,
            overwrites,
        }
    }

    fn mirror_with(channels: Vec<Channel>) -> (Identity, PermMirror) {
        let identity = Identity::generate();
        let fingerprint = identity.fingerprint();
        let info = SessionInfo {
            client_id: 1,
            server_name: "test".into(),
            server_identity: Identity::generate().public(),
            channels,
            users: vec![UserInfo {
                client_id: 1,
                identity: identity.public(),
                nickname: "me".into(),
                channel: None,
                voice: Default::default(),
                connected_at_unix_ms: 0,
                roles: Vec::new(),
                owner: false,
            }],
            roles: crate_default_roles(),
            default_channel: None,
            limits: ServerLimits::default(),
        };
        let mirror = PermMirror::from_session(fingerprint, &info);
        (identity, mirror)
    }

    /// The server's default ladder, restated here rather than imported: the
    /// mirror must work from whatever the wire says, not from server code.
    fn crate_default_roles() -> Vec<Role> {
        vec![Role {
            id: pickle_proto::EVERYONE_ROLE_ID,
            name: "everyone".into(),
            color: None,
            position: 0,
            permissions: Permissions::DEFAULT_EVERYONE,
        }]
    }

    #[test]
    fn default_bits_allow_everything_the_open_model_allowed() {
        let (_me, mirror) = mirror_with(vec![channel(1, Vec::new())]);
        let perms = mirror.my_permissions();
        let one = &perms.channels[&1];
        assert!(one.send && one.read_history && one.connect && one.speak);
        assert!(!perms.is_owner && !perms.is_admin);
    }

    #[test]
    fn a_deny_overwrite_lands_in_the_snapshot() {
        let (_me, mirror) = mirror_with(vec![channel(
            1,
            vec![Overwrite {
                target: OverwriteTarget::Role(pickle_proto::EVERYONE_ROLE_ID),
                allow: Permissions::NONE,
                deny: Permissions::SEND_MESSAGES,
            }],
        )]);
        let perms = mirror.my_permissions();
        assert!(!perms.channels[&1].send);
        assert!(perms.channels[&1].read_history, "only the denied bit goes");
    }

    #[test]
    fn a_channel_update_recomputes_the_snapshot() {
        let (_me, mut mirror) = mirror_with(vec![channel(1, Vec::new())]);
        assert!(mirror.my_permissions().channels[&1].send);

        let changed = mirror.apply(&ClientEvent::ChannelUpdated(channel(
            1,
            vec![Overwrite {
                target: OverwriteTarget::Role(pickle_proto::EVERYONE_ROLE_ID),
                allow: Permissions::NONE,
                deny: Permissions::SEND_MESSAGES,
            }],
        )));
        assert!(changed);
        assert!(!mirror.my_permissions().channels[&1].send);
    }

    #[test]
    fn a_removed_channel_leaves_the_snapshot() {
        let (_me, mut mirror) = mirror_with(vec![channel(1, Vec::new())]);
        assert!(mirror.apply(&ClientEvent::ChannelRemoved(1)));
        assert!(mirror.my_permissions().channels.is_empty());
    }

    #[test]
    fn my_role_grants_arrive_as_a_user_update_and_others_are_ignored() {
        let (me, mut mirror) = mirror_with(vec![channel(1, Vec::new())]);
        mirror.apply(&ClientEvent::RoleCreated(Role {
            id: 5,
            name: "admin".into(),
            color: None,
            position: 1,
            permissions: Permissions::ADMINISTRATOR,
        }));
        assert!(!mirror.my_permissions().is_admin);

        let update = |identity: &Identity, roles: Vec<RoleId>| {
            ClientEvent::UserUpdated(UserInfo {
                client_id: 1,
                identity: identity.public(),
                nickname: "someone".into(),
                channel: None,
                voice: Default::default(),
                connected_at_unix_ms: 0,
                roles,
                owner: false,
            })
        };

        // Another member being granted the role must not change my answer —
        // updates are matched by fingerprint, the key grants actually use.
        let stranger = Identity::generate();
        assert!(!mirror.apply(&update(&stranger, vec![5])));
        assert!(!mirror.my_permissions().is_admin);

        // The same frame about me does.
        assert!(mirror.apply(&update(&me, vec![5])));
        assert!(mirror.my_permissions().is_admin);
    }
}
