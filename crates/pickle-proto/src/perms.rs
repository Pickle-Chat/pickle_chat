//! The permission model, shared by both ends of the wire.
//!
//! The server enforces with exactly these functions and the client renders
//! with exactly these functions — one implementation of the resolution rules,
//! so the controls a client enables and the actions a server accepts can never
//! drift apart. Nothing here trusts the client: the server re-resolves every
//! action regardless of what a client believed.
//!
//! The shape is Discord's: a member's base permissions are the union of their
//! roles' bits on top of @everyone; per-channel overwrites then deny and allow
//! specific bits for roles and for individual members; `ADMINISTRATOR`
//! sidesteps overwrites entirely; the owner sidesteps everything, including
//! the hierarchy that even administrators obey.

use pickle_identity::Fingerprint;
use serde::{Deserialize, Serialize};

/// Stable identifier for a role. Ids are never reused, and id 0 is @everyone.
pub type RoleId = u32;

/// The role every member holds implicitly. Stored as an ordinary row so there
/// is exactly one code path, but pinned at position 0, undeletable, and
/// unrenamable by handler rule.
pub const EVERYONE_ROLE_ID: RoleId = 0;

/// What a member may do, as a bitset.
///
/// Bit positions are wire format **and** storage format: masks are persisted
/// in SQL and outlive any protocol bump, so a bit, once assigned, keeps its
/// position forever. New permissions append at the next free bit in their
/// group; nothing is ever renumbered — the same discipline postcard imposes on
/// enum variants. Unknown bits are carried but never granted: every check is
/// `contains` on a named bit, so a stray bit from a newer peer does nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permissions(pub u64);

impl Permissions {
    // ---- Server-wide (bits 0–15; never valid in a channel overwrite) ------

    /// Every permission everywhere, ignoring overwrites. Hierarchy still
    /// applies: an administrator cannot act on someone above them. Only the
    /// owner escapes hierarchy.
    pub const ADMINISTRATOR: Self = Self(1 << 0);
    /// Change server-wide settings.
    pub const MANAGE_SERVER: Self = Self(1 << 1);
    /// Create, edit, delete and reorder roles below your own; grant and
    /// revoke them; edit channel overwrites.
    pub const MANAGE_ROLES: Self = Self(1 << 2);
    /// Create, edit, delete and reorder channels.
    pub const MANAGE_CHANNELS: Self = Self(1 << 3);
    pub const KICK_MEMBERS: Self = Self(1 << 4);
    pub const BAN_MEMBERS: Self = Self(1 << 5);
    // Bits 6–15 reserved for future server-wide permissions.

    // ---- Channel-scoped (bits 16–47; the only bits an overwrite may touch) -

    /// See the channel and receive its traffic. Losing this hides everything
    /// else: resolution masks a channel's permissions to nothing without it,
    /// so no handler can forget to pair its own bit with visibility.
    pub const VIEW_CHANNEL: Self = Self(1 << 16);
    pub const SEND_MESSAGES: Self = Self(1 << 17);
    pub const READ_HISTORY: Self = Self(1 << 18);
    /// Delete other people's messages. Editing stays author-only forever.
    pub const MANAGE_MESSAGES: Self = Self(1 << 19);
    /// Enter a voice channel.
    pub const CONNECT: Self = Self(1 << 20);
    /// Transmit voice once connected. Not required to enter: a listen-only
    /// member in a stage-style room is a feature, not an oversight.
    pub const SPEAK: Self = Self(1 << 21);
    /// Server-mute and server-unmute members.
    pub const MUTE_MEMBERS: Self = Self(1 << 22);
    /// Move members between voice channels, or pull them out of one.
    pub const MOVE_MEMBERS: Self = Self(1 << 23);
    // Bits 24–47 reserved for future channel-scoped permissions.

    // Bits 48–62 unassigned. Bit 63 is permanently reserved so a mask always
    // fits a signed BIGINT column without sign games.

    /// Every permission this build knows.
    pub const ALL: Self = Self(
        Self::ADMINISTRATOR.0
            | Self::MANAGE_SERVER.0
            | Self::MANAGE_ROLES.0
            | Self::MANAGE_CHANNELS.0
            | Self::KICK_MEMBERS.0
            | Self::BAN_MEMBERS.0
            | Self::VIEW_CHANNEL.0
            | Self::SEND_MESSAGES.0
            | Self::READ_HISTORY.0
            | Self::MANAGE_MESSAGES.0
            | Self::CONNECT.0
            | Self::SPEAK.0
            | Self::MUTE_MEMBERS.0
            | Self::MOVE_MEMBERS.0,
    );

    /// The bits a channel overwrite may allow or deny. Resolution masks every
    /// overwrite with this, so a stored overwrite can never smuggle in a
    /// server-wide bit like `ADMINISTRATOR`.
    pub const CHANNEL_SCOPED: Self = Self(
        Self::VIEW_CHANNEL.0
            | Self::SEND_MESSAGES.0
            | Self::READ_HISTORY.0
            | Self::MANAGE_MESSAGES.0
            | Self::CONNECT.0
            | Self::SPEAK.0
            | Self::MUTE_MEMBERS.0
            | Self::MOVE_MEMBERS.0,
    );

    pub const NONE: Self = Self(0);

    /// What @everyone can do on a fresh server: exactly what an unconfigured
    /// server allows today, so upgrading changes nothing until an operator
    /// touches something.
    pub const DEFAULT_EVERYONE: Self = Self(
        Self::VIEW_CHANNEL.0
            | Self::SEND_MESSAGES.0
            | Self::READ_HISTORY.0
            | Self::CONNECT.0
            | Self::SPEAK.0,
    );

    pub const fn contains(self, bits: Self) -> bool {
        self.0 & bits.0 == bits.0
    }

    pub const fn union(self, bits: Self) -> Self {
        Self(self.0 | bits.0)
    }

    pub const fn without(self, bits: Self) -> Self {
        Self(self.0 & !bits.0)
    }

    pub const fn intersect(self, bits: Self) -> Self {
        Self(self.0 & bits.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// Bit 63 stays unassigned so a mask always round-trips a signed BIGINT.
// Compile-time: adding a bit that violates this fails the build, not a test.
const _: () = assert!(Permissions::ALL.0 < (1 << 63));

impl std::ops::BitOr for Permissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for Permissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A named bundle of permissions with a place in the hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    /// `0xRRGGBB`, or `None` for the default. Cosmetic.
    pub color: Option<u32>,
    /// Higher outranks. Positions are dense and unique — a server invariant
    /// kept by the reorder handler, relied on here for a total order.
    pub position: u32,
    pub permissions: Permissions,
}

/// One channel's exception for one role or one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overwrite {
    pub target: OverwriteTarget,
    pub allow: Permissions,
    pub deny: Permissions,
}

/// Who an overwrite applies to.
///
/// Wire note: postcard encodes the variant index, so `Role` must stay 0 and
/// `Member` must stay 1 — pinned by test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverwriteTarget {
    Role(RoleId),
    Member(Fingerprint),
}

fn role_permissions(roles: &[Role], id: RoleId) -> Permissions {
    roles
        .iter()
        .find(|r| r.id == id)
        .map(|r| r.permissions)
        .unwrap_or(Permissions::NONE)
}

fn overwrite_for_role(overwrites: &[Overwrite], id: RoleId) -> Option<&Overwrite> {
    overwrites
        .iter()
        .find(|o| o.target == OverwriteTarget::Role(id))
}

fn overwrite_for_member(overwrites: &[Overwrite], member: Fingerprint) -> Option<&Overwrite> {
    overwrites
        .iter()
        .find(|o| o.target == OverwriteTarget::Member(member))
}

/// The permissions `member` holds — server-wide when `channel_overwrites` is
/// `None`, or inside one channel when it carries that channel's overwrites
/// (possibly empty). Pure; the caller supplies snapshots.
///
/// * `roles` — every server role, @everyone included.
/// * `member_roles` — the member's explicit grants; @everyone is implicit.
///   Ids naming deleted roles are skipped, so deleting a role demotes its
///   holders rather than erroring.
pub fn resolve(
    roles: &[Role],
    member_roles: &[RoleId],
    member: Fingerprint,
    owner: bool,
    channel_overwrites: Option<&[Overwrite]>,
) -> Permissions {
    if owner {
        return Permissions::ALL;
    }

    // 1. Base: @everyone plus the union of explicit roles.
    let mut base = role_permissions(roles, EVERYONE_ROLE_ID);
    for id in member_roles {
        base |= role_permissions(roles, *id);
    }

    // 2. An administrator holds everything, and overwrites are ignored.
    if base.contains(Permissions::ADMINISTRATOR) {
        return Permissions::ALL;
    }

    let Some(overwrites) = channel_overwrites else {
        return base;
    };
    let mut perms = base;

    // 3. The @everyone overwrite: deny, then allow.
    if let Some(ow) = overwrite_for_role(overwrites, EVERYONE_ROLE_ID) {
        perms = perms.without(ow.deny.intersect(Permissions::CHANNEL_SCOPED));
        perms |= ow.allow.intersect(Permissions::CHANNEL_SCOPED);
    }

    // 4. Role overwrites: the union of ALL denies, then the union of ALL
    //    allows — so one role's allow beats another role's deny, whatever
    //    order the overwrites are stored in.
    let (mut denies, mut allows) = (Permissions::NONE, Permissions::NONE);
    for id in member_roles {
        if let Some(ow) = overwrite_for_role(overwrites, *id) {
            denies |= ow.deny;
            allows |= ow.allow;
        }
    }
    perms = perms.without(denies.intersect(Permissions::CHANNEL_SCOPED));
    perms |= allows.intersect(Permissions::CHANNEL_SCOPED);

    // 5. The member overwrite: deny, then allow. Beats everything above.
    if let Some(ow) = overwrite_for_member(overwrites, member) {
        perms = perms.without(ow.deny.intersect(Permissions::CHANNEL_SCOPED));
        perms |= ow.allow.intersect(Permissions::CHANNEL_SCOPED);
    }

    // 6. A channel you cannot see grants nothing. Discord enforces the same
    //    outcome endpoint by endpoint; folding it into resolution means no
    //    handler here can forget the pairing.
    if !perms.contains(Permissions::VIEW_CHANNEL) {
        return Permissions::NONE;
    }
    perms
}

/// The member's most senior role position — 0 with no roles, since @everyone
/// sits at position 0.
pub fn top_role_position(roles: &[Role], member_roles: &[RoleId]) -> u32 {
    member_roles
        .iter()
        .filter_map(|id| roles.iter().find(|r| r.id == *id))
        .map(|r| r.position)
        .max()
        .unwrap_or(0)
}

/// May the actor kick, ban, server-mute or move the target? Permission bits
/// are the caller's problem; this is rank alone.
///
/// `ADMINISTRATOR` does **not** bypass this — an admin still cannot act on
/// someone above them. The owner bypasses it and is immune: promoting someone
/// must never be a way to lose your own server. Equal top positions block in
/// both directions, so two moderators cannot strip each other — and since the
/// same fingerprint always has the same position, nobody acts on themselves
/// by accident either.
pub fn can_act_on(
    roles: &[Role],
    actor_roles: &[RoleId],
    actor_owner: bool,
    target_roles: &[RoleId],
    target_owner: bool,
) -> bool {
    if target_owner {
        return false;
    }
    if actor_owner {
        return true;
    }
    top_role_position(roles, actor_roles) > top_role_position(roles, target_roles)
}

/// May the actor create at, edit, delete, grant or revoke this role? The
/// strictly-below rule: a role at your own top position is out of reach, so
/// two holders of the same top role cannot strip each other.
///
/// Granting checks this on **the role being granted**, not rank against the
/// recipient — you may hand a junior role to anyone, even your senior.
/// @everyone (position 0) is editable by anyone who outranks position 0 and
/// holds the bit; that it is undeletable and unmovable is a handler rule, not
/// a rank rule.
pub fn can_manage_role(
    roles: &[Role],
    actor_roles: &[RoleId],
    actor_owner: bool,
    role: RoleId,
) -> bool {
    if actor_owner {
        return true;
    }
    let Some(target) = roles.iter().find(|r| r.id == role) else {
        return false;
    };
    target.position < top_role_position(roles, actor_roles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;

    fn fp() -> Fingerprint {
        Identity::generate().fingerprint()
    }

    fn role(id: RoleId, position: u32, permissions: Permissions) -> Role {
        Role {
            id,
            name: format!("role-{id}"),
            color: None,
            position,
            permissions,
        }
    }

    /// A ladder with @everyone holding the fresh-server defaults.
    fn ladder() -> Vec<Role> {
        vec![
            role(EVERYONE_ROLE_ID, 0, Permissions::DEFAULT_EVERYONE),
            role(1, 1, Permissions::KICK_MEMBERS),
            role(2, 2, Permissions::ADMINISTRATOR),
        ]
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

    // ---- resolution --------------------------------------------------------

    #[test]
    fn base_is_the_union_of_everyone_and_explicit_roles() {
        let perms = resolve(&ladder(), &[1], fp(), false, None);
        assert!(perms.contains(Permissions::DEFAULT_EVERYONE));
        assert!(perms.contains(Permissions::KICK_MEMBERS));
        assert!(!perms.contains(Permissions::BAN_MEMBERS));
    }

    #[test]
    fn owner_resolves_to_everything_even_under_a_member_deny() {
        let me = fp();
        let overwrites = [deny(OverwriteTarget::Member(me), Permissions::VIEW_CHANNEL)];
        let perms = resolve(&ladder(), &[], me, true, Some(&overwrites));
        assert_eq!(perms, Permissions::ALL);
    }

    #[test]
    fn administrator_in_base_grants_everything_and_ignores_overwrites() {
        let me = fp();
        let overwrites = [deny(
            OverwriteTarget::Role(EVERYONE_ROLE_ID),
            Permissions::VIEW_CHANNEL,
        )];
        let perms = resolve(&ladder(), &[2], me, false, Some(&overwrites));
        assert_eq!(perms, Permissions::ALL);
    }

    #[test]
    fn administrator_via_any_held_role_counts() {
        // The bit sits on a role, not on @everyone; holding the role is enough.
        let roles = vec![
            role(EVERYONE_ROLE_ID, 0, Permissions::NONE),
            role(7, 1, Permissions::ADMINISTRATOR),
        ];
        assert_eq!(resolve(&roles, &[7], fp(), false, None), Permissions::ALL);
    }

    #[test]
    fn no_channel_returns_the_base() {
        let perms = resolve(&ladder(), &[], fp(), false, None);
        assert_eq!(perms, Permissions::DEFAULT_EVERYONE);
    }

    #[test]
    fn everyone_overwrite_deny_removes_a_base_bit() {
        let overwrites = [deny(
            OverwriteTarget::Role(EVERYONE_ROLE_ID),
            Permissions::SEND_MESSAGES,
        )];
        let perms = resolve(&ladder(), &[], fp(), false, Some(&overwrites));
        assert!(!perms.contains(Permissions::SEND_MESSAGES));
        assert!(perms.contains(Permissions::VIEW_CHANNEL));
    }

    #[test]
    fn role_overwrite_allow_beats_the_everyone_overwrite_deny() {
        let overwrites = [
            deny(
                OverwriteTarget::Role(EVERYONE_ROLE_ID),
                Permissions::SEND_MESSAGES,
            ),
            allow(OverwriteTarget::Role(1), Permissions::SEND_MESSAGES),
        ];
        let perms = resolve(&ladder(), &[1], fp(), false, Some(&overwrites));
        assert!(perms.contains(Permissions::SEND_MESSAGES));
    }

    #[test]
    fn one_roles_allow_beats_another_roles_deny() {
        // All denies are unioned before all allows, so order between roles
        // never matters and allow wins.
        let roles = vec![
            role(EVERYONE_ROLE_ID, 0, Permissions::DEFAULT_EVERYONE),
            role(1, 1, Permissions::NONE),
            role(2, 2, Permissions::NONE),
        ];
        let overwrites = [
            deny(OverwriteTarget::Role(1), Permissions::SEND_MESSAGES),
            allow(OverwriteTarget::Role(2), Permissions::SEND_MESSAGES),
        ];
        let forward = resolve(&roles, &[1, 2], fp(), false, Some(&overwrites));
        let reverse = resolve(&roles, &[2, 1], fp(), false, Some(&overwrites));
        assert!(forward.contains(Permissions::SEND_MESSAGES));
        assert_eq!(forward, reverse);
    }

    #[test]
    fn member_overwrite_deny_beats_a_role_overwrite_allow() {
        let me = fp();
        let overwrites = [
            allow(OverwriteTarget::Role(1), Permissions::SEND_MESSAGES),
            deny(OverwriteTarget::Member(me), Permissions::SEND_MESSAGES),
        ];
        let perms = resolve(&ladder(), &[1], me, false, Some(&overwrites));
        assert!(!perms.contains(Permissions::SEND_MESSAGES));
    }

    #[test]
    fn member_overwrite_allow_beats_every_role_deny() {
        let me = fp();
        let overwrites = [
            deny(
                OverwriteTarget::Role(EVERYONE_ROLE_ID),
                Permissions::SEND_MESSAGES,
            ),
            deny(OverwriteTarget::Role(1), Permissions::SEND_MESSAGES),
            allow(OverwriteTarget::Member(me), Permissions::SEND_MESSAGES),
        ];
        let perms = resolve(&ladder(), &[1], me, false, Some(&overwrites));
        assert!(perms.contains(Permissions::SEND_MESSAGES));
    }

    #[test]
    fn a_bit_in_both_allow_and_deny_of_one_overwrite_resolves_to_allow() {
        // Deny is applied first, then allow — within a single overwrite the
        // allow half wins. Handlers refuse to *store* overlapping overwrites,
        // but resolution stays total for whatever is already stored.
        let overwrites = [Overwrite {
            target: OverwriteTarget::Role(EVERYONE_ROLE_ID),
            allow: Permissions::SEND_MESSAGES,
            deny: Permissions::SEND_MESSAGES,
        }];
        let perms = resolve(&ladder(), &[], fp(), false, Some(&overwrites));
        assert!(perms.contains(Permissions::SEND_MESSAGES));
    }

    #[test]
    fn overwrites_for_roles_the_member_lacks_do_nothing() {
        let overwrites = [deny(OverwriteTarget::Role(1), Permissions::SEND_MESSAGES)];
        let perms = resolve(&ladder(), &[], fp(), false, Some(&overwrites));
        assert!(perms.contains(Permissions::SEND_MESSAGES));
    }

    #[test]
    fn overwrites_for_other_members_do_nothing() {
        let overwrites = [deny(
            OverwriteTarget::Member(fp()),
            Permissions::SEND_MESSAGES,
        )];
        let perms = resolve(&ladder(), &[], fp(), false, Some(&overwrites));
        assert!(perms.contains(Permissions::SEND_MESSAGES));
    }

    #[test]
    fn overwrites_cannot_touch_server_wide_bits() {
        // ADMINISTRATOR in an overwrite allow is inert: overwrites are masked
        // to the channel-scoped bits during resolution, so a stored overwrite
        // can never mint a server-wide power.
        let me = fp();
        let overwrites = [allow(
            OverwriteTarget::Member(me),
            Permissions::ADMINISTRATOR,
        )];
        let perms = resolve(&ladder(), &[], me, false, Some(&overwrites));
        assert!(!perms.contains(Permissions::ADMINISTRATOR));
    }

    #[test]
    fn a_deleted_role_in_the_membership_list_demotes_rather_than_erroring() {
        let perms = resolve(&ladder(), &[999], fp(), false, None);
        assert_eq!(perms, Permissions::DEFAULT_EVERYONE);
    }

    #[test]
    fn losing_view_channel_masks_every_other_bit() {
        let overwrites = [deny(
            OverwriteTarget::Role(EVERYONE_ROLE_ID),
            Permissions::VIEW_CHANNEL,
        )];
        let perms = resolve(&ladder(), &[1], fp(), false, Some(&overwrites));
        assert_eq!(
            perms,
            Permissions::NONE,
            "a channel you cannot see grants nothing at all"
        );
    }

    #[test]
    fn unknown_bits_are_carried_but_grant_nothing() {
        let future_bit = Permissions(1 << 40);
        let roles = vec![role(
            EVERYONE_ROLE_ID,
            0,
            Permissions::DEFAULT_EVERYONE.union(future_bit),
        )];
        let perms = resolve(&roles, &[], fp(), false, None);
        assert!(perms.contains(future_bit), "carried");
        assert!(!perms.contains(Permissions::ADMINISTRATOR), "not granted");
    }

    // ---- hierarchy ---------------------------------------------------------

    #[test]
    fn a_member_with_no_roles_sits_at_position_zero() {
        assert_eq!(top_role_position(&ladder(), &[]), 0);
    }

    #[test]
    fn acting_on_someone_requires_a_strictly_higher_top_role() {
        let roles = ladder();
        assert!(can_act_on(&roles, &[2], false, &[1], false));
        assert!(!can_act_on(&roles, &[1], false, &[2], false));
    }

    #[test]
    fn equal_top_roles_cannot_act_on_each_other() {
        // Two moderators cannot kick each other — kept from the old suite.
        let roles = ladder();
        assert!(!can_act_on(&roles, &[1], false, &[1], false));
    }

    #[test]
    fn the_owner_acts_on_anyone_and_is_never_acted_on() {
        let roles = ladder();
        assert!(can_act_on(&roles, &[], true, &[2], false));
        assert!(!can_act_on(&roles, &[2], false, &[], true));
        assert!(!can_act_on(&roles, &[], true, &[], true));
    }

    #[test]
    fn an_administrator_does_not_bypass_hierarchy() {
        let roles = vec![
            role(EVERYONE_ROLE_ID, 0, Permissions::NONE),
            role(1, 1, Permissions::ADMINISTRATOR),
            role(2, 2, Permissions::NONE),
        ];
        assert!(
            !can_act_on(&roles, &[1], false, &[2], false),
            "the bit grants powers, never seniority"
        );
    }

    #[test]
    fn managing_a_role_requires_a_strictly_higher_top_role() {
        let roles = ladder();
        assert!(can_manage_role(&roles, &[2], false, 1));
        assert!(!can_manage_role(&roles, &[1], false, 2));
    }

    #[test]
    fn your_own_top_role_is_out_of_your_reach() {
        // Otherwise two holders of the same top role could strip each other.
        let roles = ladder();
        assert!(!can_manage_role(&roles, &[1], false, 1));
    }

    #[test]
    fn a_roleless_member_cannot_manage_everyone() {
        // Position 0 is not strictly below position 0.
        let roles = ladder();
        assert!(!can_manage_role(&roles, &[], false, EVERYONE_ROLE_ID));
    }

    #[test]
    fn a_member_with_any_role_can_manage_everyone_given_the_bit() {
        let roles = ladder();
        assert!(can_manage_role(&roles, &[1], false, EVERYONE_ROLE_ID));
    }

    #[test]
    fn the_owner_manages_every_role() {
        let roles = ladder();
        assert!(can_manage_role(&roles, &[], true, 2));
        assert!(can_manage_role(&roles, &[], true, EVERYONE_ROLE_ID));
    }

    #[test]
    fn granting_a_junior_role_does_not_require_outranking_the_recipient() {
        // The check is on the role being granted; the recipient's own rank is
        // irrelevant. A moderator may hand "member" to an admin.
        let roles = ladder();
        assert!(can_manage_role(&roles, &[2], false, 1));
    }

    #[test]
    fn a_managed_role_that_does_not_exist_is_refused() {
        assert!(!can_manage_role(&ladder(), &[2], false, 999));
    }

    // ---- pins --------------------------------------------------------------

    #[test]
    fn permission_bits_keep_their_positions() {
        // Bits are wire format AND storage format: a persisted mask outlives
        // any protocol bump, so a bit, once assigned, is assigned forever.
        assert_eq!(Permissions::ADMINISTRATOR.0, 1 << 0);
        assert_eq!(Permissions::MANAGE_SERVER.0, 1 << 1);
        assert_eq!(Permissions::MANAGE_ROLES.0, 1 << 2);
        assert_eq!(Permissions::MANAGE_CHANNELS.0, 1 << 3);
        assert_eq!(Permissions::KICK_MEMBERS.0, 1 << 4);
        assert_eq!(Permissions::BAN_MEMBERS.0, 1 << 5);
        assert_eq!(Permissions::VIEW_CHANNEL.0, 1 << 16);
        assert_eq!(Permissions::SEND_MESSAGES.0, 1 << 17);
        assert_eq!(Permissions::READ_HISTORY.0, 1 << 18);
        assert_eq!(Permissions::MANAGE_MESSAGES.0, 1 << 19);
        assert_eq!(Permissions::CONNECT.0, 1 << 20);
        assert_eq!(Permissions::SPEAK.0, 1 << 21);
        assert_eq!(Permissions::MUTE_MEMBERS.0, 1 << 22);
        assert_eq!(Permissions::MOVE_MEMBERS.0, 1 << 23);
        assert!(Permissions::ALL.contains(Permissions::CHANNEL_SCOPED));
    }

    #[test]
    fn overwrite_target_variants_keep_their_wire_positions() {
        let encoded = postcard::to_stdvec(&OverwriteTarget::Role(1)).unwrap();
        assert_eq!(encoded[0], 0, "Role must stay at index 0");
        let encoded = postcard::to_stdvec(&OverwriteTarget::Member(fp())).unwrap();
        assert_eq!(encoded[0], 1, "Member must stay at index 1");
    }

    #[test]
    fn wire_roundtrips_survive_postcard() {
        let original = Role {
            id: 3,
            name: "dj".into(),
            color: Some(0x00ff_88aa),
            position: 4,
            permissions: Permissions::DEFAULT_EVERYONE,
        };
        let bytes = postcard::to_stdvec(&original).unwrap();
        let decoded: Role = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, original);

        let member = fp();
        let ow = Overwrite {
            target: OverwriteTarget::Member(member),
            allow: Permissions::SEND_MESSAGES,
            deny: Permissions::CONNECT,
        };
        let bytes = postcard::to_stdvec(&ow).unwrap();
        let decoded: Overwrite = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, ow);
    }
}
