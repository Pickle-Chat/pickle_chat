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
    /// Any administrative standing at all — what gates the gear.
    pub can_open_admin: bool,
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
    /// A fingerprint belonging to nobody, for answering "what would a member
    /// holding only role X get" — a hypothetical must never collide with a
    /// real member overwrite.
    probe: Fingerprint,
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

/// A role as the interface renders it.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RoleDto {
    pub id: RoleId,
    pub name: String,
    /// "#rrggbb", or null for the default.
    pub color: Option<String>,
    pub position: u32,
    /// Named bits, never numbers: the Rust side owns all bit math.
    pub permissions: Vec<&'static str>,
    pub is_everyone: bool,
}

/// The permission names an editor can toggle, with their bits — one list for
/// the whole interface, exhaustively matched so a new bit cannot be missed.
pub const EDITABLE_PERMISSIONS: &[(&str, Permissions)] = &[
    ("administrator", Permissions::ADMINISTRATOR),
    ("manageServer", Permissions::MANAGE_SERVER),
    ("manageRoles", Permissions::MANAGE_ROLES),
    ("manageChannels", Permissions::MANAGE_CHANNELS),
    ("kickMembers", Permissions::KICK_MEMBERS),
    ("banMembers", Permissions::BAN_MEMBERS),
    ("viewChannel", Permissions::VIEW_CHANNEL),
    ("sendMessages", Permissions::SEND_MESSAGES),
    ("readHistory", Permissions::READ_HISTORY),
    ("manageMessages", Permissions::MANAGE_MESSAGES),
    ("connect", Permissions::CONNECT),
    ("speak", Permissions::SPEAK),
    ("muteMembers", Permissions::MUTE_MEMBERS),
    ("moveMembers", Permissions::MOVE_MEMBERS),
];

/// The channel-scoped bits in display order — the matrix's columns.
pub const CHANNEL_PERMISSIONS: &[(&str, Permissions)] = &[
    ("viewChannel", Permissions::VIEW_CHANNEL),
    ("sendMessages", Permissions::SEND_MESSAGES),
    ("readHistory", Permissions::READ_HISTORY),
    ("manageMessages", Permissions::MANAGE_MESSAGES),
    ("connect", Permissions::CONNECT),
    ("speak", Permissions::SPEAK),
    ("muteMembers", Permissions::MUTE_MEMBERS),
    ("moveMembers", Permissions::MOVE_MEMBERS),
];

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MatrixRowDto {
    pub role_id: RoleId,
    pub role_name: String,
    pub color: Option<String>,
    pub is_everyone: bool,
    pub cells: Vec<MatrixCellDto>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MatrixCellDto {
    pub name: &'static str,
    /// What a member holding only this role ends up with here.
    pub effective: bool,
    /// What the role's bits alone would give, before overwrites.
    pub base: bool,
    /// This role's overwrite for this bit: "allow", "deny", or "inherit".
    pub state: &'static str,
}

pub fn permission_names(bits: Permissions) -> Vec<&'static str> {
    EDITABLE_PERMISSIONS
        .iter()
        .filter(|(_, bit)| bits.contains(*bit))
        .map(|(name, _)| *name)
        .collect()
}

pub fn permissions_from_names(names: &[String]) -> Permissions {
    let mut bits = Permissions::NONE;
    for name in names {
        if let Some((_, bit)) = EDITABLE_PERMISSIONS.iter().find(|(n, _)| n == name) {
            bits = bits.union(*bit);
        }
    }
    bits
}

fn role_dto(role: &Role) -> RoleDto {
    RoleDto {
        id: role.id,
        name: role.name.clone(),
        color: role.color.map(|c| format!("#{c:06x}")),
        position: role.position,
        permissions: permission_names(role.permissions),
        is_everyone: role.id == pickle_proto::EVERYONE_ROLE_ID,
    }
}

/// One channel overwrite as the tri-state editor renders it.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OverwriteDto {
    pub target: OverwriteTargetDto,
    pub allow: Vec<&'static str>,
    pub deny: Vec<&'static str>,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum OverwriteTargetDto {
    Role { id: RoleId },
    Member { fingerprint: String },
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
            probe: pickle_identity::Identity::generate().fingerprint(),
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
        let standing = [
            Permissions::MANAGE_SERVER,
            Permissions::MANAGE_ROLES,
            Permissions::MANAGE_CHANNELS,
            Permissions::KICK_MEMBERS,
            Permissions::BAN_MEMBERS,
            Permissions::MUTE_MEMBERS,
            Permissions::MOVE_MEMBERS,
        ]
        .iter()
        .any(|bit| base.contains(*bit));
        MyPermissionsDto {
            is_owner: self.owner,
            is_admin: base.contains(Permissions::ADMINISTRATOR),
            can_open_admin: self.owner || standing,
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

    /// Every role, sorted senior-first for display.
    pub fn roles_dto(&self) -> Vec<RoleDto> {
        let mut roles: Vec<RoleDto> = self.roles.iter().map(role_dto).collect();
        roles.sort_by_key(|r| std::cmp::Reverse(r.position));
        roles
    }

    /// One channel's overwrites, for the tri-state editor.
    pub fn overwrites_dto(&self, channel: ChannelId) -> Vec<OverwriteDto> {
        use pickle_proto::OverwriteTarget;
        self.channels
            .get(&channel)
            .map(|c| {
                c.overwrites
                    .iter()
                    .map(|o| OverwriteDto {
                        target: match &o.target {
                            OverwriteTarget::Role(id) => OverwriteTargetDto::Role { id: *id },
                            OverwriteTarget::Member(fp) => OverwriteTargetDto::Member {
                                fingerprint: fp.to_string(),
                            },
                        },
                        allow: permission_names(o.allow),
                        deny: permission_names(o.deny),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What each role means inside one channel: the resolved bits a member
    /// holding only that role would have, cell by cell, with each cell naming
    /// whether an overwrite forced it away from the role's base. The grid the
    /// interface renders and edits in place.
    ///
    /// Per-role, deliberately: real members union several roles, so a
    /// member's effective bits can exceed any single row — the matrix answers
    /// "what does this role contribute", not "what does this person get".
    pub fn channel_matrix(&self, channel: ChannelId) -> Vec<MatrixRowDto> {
        let Some(target) = self.channels.get(&channel) else {
            return Vec::new();
        };
        let mut rows: Vec<&Role> = self.roles.iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.position));
        rows.iter()
            .map(|role| {
                let held = if role.id == pickle_proto::EVERYONE_ROLE_ID {
                    vec![]
                } else {
                    vec![role.id]
                };
                let base = resolve(&self.roles, &held, self.probe, false, None);
                let effective = resolve(
                    &self.roles,
                    &held,
                    self.probe,
                    false,
                    Some(&target.overwrites),
                );
                let overwrite = target
                    .overwrites
                    .iter()
                    .find(|o| o.target == pickle_proto::OverwriteTarget::Role(role.id));
                MatrixRowDto {
                    role_id: role.id,
                    role_name: role.name.clone(),
                    color: role.color.map(|c| format!("#{c:06x}")),
                    is_everyone: role.id == pickle_proto::EVERYONE_ROLE_ID,
                    cells: CHANNEL_PERMISSIONS
                        .iter()
                        .map(|(name, bit)| {
                            let state = match overwrite {
                                Some(o) if o.deny.contains(*bit) => "deny",
                                Some(o) if o.allow.contains(*bit) => "allow",
                                _ => "inherit",
                            };
                            MatrixCellDto {
                                name,
                                effective: effective.contains(*bit),
                                base: base.contains(*bit),
                                state,
                            }
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// Did this event change the role table? The pump re-emits the roles
    /// snapshot when it did, alongside the permissions snapshot.
    pub fn touches_roles(event: &ClientEvent) -> bool {
        matches!(
            event,
            ClientEvent::RoleCreated(_)
                | ClientEvent::RoleUpdated(_)
                | ClientEvent::RoleDeleted { .. }
                | ClientEvent::RolesReordered { .. }
        )
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

    fn allow(target: OverwriteTarget, bits: Permissions) -> Overwrite {
        Overwrite {
            target,
            allow: bits,
            deny: Permissions::NONE,
        }
    }

    fn deny(target: OverwriteTarget, bits: Permissions) -> Overwrite {
        Overwrite {
            target,
            allow: Permissions::NONE,
            deny: bits,
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
    fn the_matrix_names_base_overridden_and_hidden_cells() {
        let (_me, mut mirror) = mirror_with(vec![channel(1, Vec::new())]);
        mirror.apply(&ClientEvent::RoleCreated(Role {
            id: 5,
            name: "dj".into(),
            color: None,
            position: 1,
            permissions: Permissions::NONE,
        }));

        // Deny everyone's sendMessages; allow it back for dj.
        mirror.apply(&ClientEvent::ChannelUpdated(channel(
            1,
            vec![
                deny(
                    OverwriteTarget::Role(pickle_proto::EVERYONE_ROLE_ID),
                    Permissions::SEND_MESSAGES,
                ),
                allow(OverwriteTarget::Role(5), Permissions::SEND_MESSAGES),
            ],
        )));

        let matrix = mirror.channel_matrix(1);
        let everyone = matrix.iter().find(|r| r.is_everyone).unwrap();
        let dj = matrix.iter().find(|r| r.role_id == 5).unwrap();

        let send = |row: &MatrixRowDto| {
            row.cells
                .iter()
                .find(|c| c.name == "sendMessages")
                .unwrap()
                .clone()
        };
        let e = send(everyone);
        assert!(e.base && !e.effective, "denied away from its base");
        assert_eq!(e.state, "deny");

        let d = send(dj);
        // dj's base includes everyone's bits (a member holds both), and the
        // allow overwrite keeps it effective despite everyone's deny.
        assert!(d.effective);
        assert_eq!(d.state, "allow");

        // A viewChannel deny hides everything: every cell goes dark.
        mirror.apply(&ClientEvent::ChannelUpdated(channel(
            1,
            vec![deny(
                OverwriteTarget::Role(pickle_proto::EVERYONE_ROLE_ID),
                Permissions::VIEW_CHANNEL,
            )],
        )));
        let matrix = mirror.channel_matrix(1);
        let everyone = matrix.iter().find(|r| r.is_everyone).unwrap();
        assert!(everyone.cells.iter().all(|c| !c.effective));
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
