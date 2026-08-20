// The typed edge of the Rust bridge.
//
// Every call into Rust goes through here so the shapes live in one place and
// the components stay free of `invoke` string literals.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Identity {
  fingerprint: string;
  short: string;
  securityLevel: number;
  nickname: string;
}

export interface VaultEntry {
  fingerprint: string;
  short: string;
  securityLevel: number;
  nickname: string;
  /// Private note, never sent to a server.
  label: string;
}

export interface IdentityList {
  /// Fingerprint of the active identity.
  active: string;
  identities: VaultEntry[];
}

/** The shape `connect` rejects with. Everything is a message; an identity
    change additionally carries the parts needed to act on it. */
export interface ConnectFailure {
  message: string;
  identityChanged: {
    /** The key the pin is filed under — pass back to trustChangedIdentity. */
    addressKey: string;
    previous: string;
    current: string;
  } | null;
}

/** A rejected invoke can carry our structured failure or a plain string. */
export function describeError(err: unknown): string {
  if (typeof err === "object" && err !== null && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return String(err);
}

export function identityChangeOf(err: unknown): ConnectFailure["identityChanged"] {
  if (typeof err === "object" && err !== null && "identityChanged" in err) {
    return (err as ConnectFailure).identityChanged;
  }
  return null;
}

export interface Channel {
  id: number;
  parent: number | null;
  name: string;
  topic: string;
  hasVoice: boolean;
  hasText: boolean;
  order: number;
}

export interface User {
  clientId: number;
  nickname: string;
  /** Full fingerprint — the stable key for role grants, bans, verification. */
  fingerprint: string;
  /** Abbreviated form for display. */
  short: string;
  securityLevel: number;
  channel: number | null;
  selfMuted: boolean;
  selfDeafened: boolean;
  /** Muted by a moderator, not by choice. */
  serverMuted: boolean;
  /** Role grants, @everyone implicit. */
  roles: number[];
}

export interface Message {
  id: number;
  channel: number;
  authorNickname: string;
  authorFingerprint: string;
  content: string;
  sentAtUnixMs: number;
}

/** Resolved by the Rust side with the same rules the server enforces; this
    layer only renders the booleans. Replaced wholesale by permissionsChanged. */
export interface ChannelPermissions {
  send: boolean;
  readHistory: boolean;
  connect: boolean;
  speak: boolean;
}

export interface Role {
  id: number;
  name: string;
  /** "#rrggbb" or null. */
  color: string | null;
  /** Higher outranks. */
  position: number;
  permissions: Permission[];
  isEveryone: boolean;
}

/** Every permission name the editor can toggle — mirrors the Rust list. */
export type Permission =
  | "administrator"
  | "manageServer"
  | "manageRoles"
  | "manageChannels"
  | "kickMembers"
  | "banMembers"
  | "viewChannel"
  | "sendMessages"
  | "readHistory"
  | "manageMessages"
  | "connect"
  | "speak"
  | "muteMembers"
  | "moveMembers";

export type OverwriteTarget =
  | { kind: "role"; id: number }
  | { kind: "member"; fingerprint: string };

export interface Overwrite {
  target: OverwriteTarget;
  allow: Permission[];
  deny: Permission[];
}

export interface BanEntry {
  fingerprint: string;
  short: string;
  reason: string;
  untilUnixMs: number | null;
  issuedByShort: string;
  issuedAtUnixMs: number;
}

export interface ModerationOptions {
  canKick: boolean;
  canBan: boolean;
  canMute: boolean;
  canMove: boolean;
  /** One honest sentence when everything above is false. */
  reason: string | null;
}

export interface MyPermissions {
  isOwner: boolean;
  isAdmin: boolean;
  /** Any administrative standing at all — gates the admin gear. */
  canOpenAdmin: boolean;
  channels: Record<number, ChannelPermissions>;
}

export interface Session {
  clientId: number;
  serverName: string;
  serverFingerprint: string;
  /** Where the server placed us — null on a server with nowhere voiceless to land. */
  defaultChannel: number | null;
  channels: Channel[];
  users: User[];
}

/// Identifies one connection for the lifetime of the process. Never reused, so
/// a stale id from a closed tab fails rather than addressing another server.
export type SessionId = number;

export interface Connection {
  permissions: MyPermissions;
  roles: Role[];
  session: SessionId;
  info: Session;
  /// Fingerprint of the identity this connection signed in with, which need not
  /// be the currently active one.
  identity: string;
}

export interface SessionList {
  sessions: Connection[];
  /// Which connection the microphone feeds, if any.
  voice: SessionId | null;
}

/// Who is audible, and where. Speaker ids only mean something within one
/// server, so the session is part of the answer rather than assumed.
export interface Speaking {
  session: SessionId | null;
  clients: number[];
}

export interface AudioDevice {
  name: string;
  isDefault: boolean;
  /// False only when the device offers no sample format Pickle can read. A
  /// device running at some rate other than 48 kHz is converted, not refused.
  usable: boolean;
  /// The rate the device would be opened at, or null if it could not be
  /// queried. Anything but 48000 means a conversion sits in the path.
  sampleRate: number | null;
}

export interface AudioDevices {
  inputs: AudioDevice[];
  outputs: AudioDevice[];
}

export interface MiningProgress {
  bestLevel: number;
  hashes: number;
  done: boolean;
}

/** Stable names for the server's refusal codes, mirrored from the Rust side's
    exhaustive mapping — a new code is a compile error there, not a mystery
    string here. */
export type ServerErrorCode =
  | "notAuthenticated"
  | "noSuchChannel"
  | "noSuchMessage"
  | "channelFull"
  | "channelPasswordRequired"
  | "notPermitted"
  | "rateLimited"
  | "messageTooLong"
  | "malformed"
  | "internal";

export type ServerEvent =
  | { type: "userJoined"; user: User }
  | { type: "userLeft"; clientId: number; reason: "left" | "kicked" | "banned" }
  | { type: "userMoved"; clientId: number; channel: number | null }
  | { type: "userUpdated"; user: User }
  | { type: "message"; message: Message }
  | { type: "history"; channel: number; messages: Message[]; reachedStart: boolean }
  | { type: "typing"; clientId: number; channel: number }
  | { type: "channelCreated"; channel: Channel }
  | { type: "channelUpdated"; channel: Channel }
  | { type: "channelRemoved"; channelId: number }
  | { type: "rolesChanged"; roles: Role[] }
  | { type: "banList"; bans: BanEntry[] }
  | { type: "commandFailed"; nonce: number; code: ServerErrorCode; detail: string }
  | { type: "permissionsChanged"; permissions: MyPermissions }
  | { type: "serverError"; code: ServerErrorCode; detail: string }
  | { type: "disconnected"; reason: string };

export type GateMode = "voiceActivity" | "pushToTalk" | "continuous";

export interface AudioSettings {
  // Undefined means the system default device.
  inputDevice: string | null;
  outputDevice: string | null;
  bitrate: number;
  gateMode: GateMode;
}

/// Accelerators in Tauri's syntax, or null when unbound.
export interface Keybinds {
  pushToTalk: string | null;
  toggleMute: string | null;
  toggleDeafen: string | null;
}

/// A connection that was open when the app last recorded its state.
///
/// No password: bookmarks hold those, matched by address when reconnecting.
export interface OpenConnection {
  address: string;
  /// Fingerprint of the identity it signed in with, so a restore returns as the
  /// same person rather than as whoever happens to be active.
  identity: string;
}

export interface Settings {
  audio: AudioSettings;
  keybinds: Keybinds;
  connections: OpenConnection[];
}

export interface Bookmark {
  id: number;
  label: string;
  address: string;
  password?: string;
  /// Fingerprint of the identity to connect with, when a particular one is
  /// wanted for this server.
  identity?: string;
}

export interface BookmarkInput {
  [key: string]: unknown;
  label: string;
  address: string;
  password?: string;
  identity?: string;
}

export type KeybindAction = "pushToTalk" | "toggleMute" | "toggleDeafen";

/// How far a binding reaches. Deliberately not a boolean: an X11 grab takes the
/// key away from every other application, while the XWayland grab that a
/// Wayland session gets instead is delivered to the focused window as well. See
/// the note in the Rust `shortcuts` module.
export type Reach = "exclusive" | "shared" | "device" | "focused";

export interface BindingStatus {
  action: KeybindAction;
  accelerator: string;
  reach: Reach;
  /// Why the reach is what it is. Absent only for `exclusive`, the one case
  /// that needs no explanation.
  note: string | null;
}

/// One mouse, identified the way a udev rule identifies it.
export interface MouseDevice {
  name: string;
  vendor: string;
  product: string;
}

/// A udev rule granting access to the mice Pickle cannot currently read.
///
/// The point of shipping this rather than telling people to join the `input`
/// group: the group would hand every process they run a permanent read on every
/// keyboard on the machine, where this grants one mouse to one session.
export interface MouseAccess {
  path: string;
  rule: string;
  devices: MouseDevice[];
}

export interface VoiceState {
  muted: boolean;
  deafened: boolean;
}

export interface InputActivity {
  levelDbfs: number;
  /// Whether audio is actually going out, which the level alone cannot say: a
  /// loud room with the gate shut moves the meter and sends nothing.
  transmitting: boolean;
}

// The index signature is what `invoke` requires of its argument object; the
// named fields are what actually keeps call sites honest.
//
// Audio is deliberately absent: devices and gate mode live in settings, which
// can change them while connected.
export interface ConnectRequest {
  [key: string]: unknown;
  address: string;
  password?: string;
  /// Fingerprint of the identity to sign in with. Omitted means the active one.
  identity?: string;
}

export const api = {
  identityInfo: () => invoke<Identity>("identity_info"),
  setNickname: (nickname: string) => invoke<Identity>("set_nickname", { nickname }),
  mineIdentity: (targetLevel: number) => invoke<void>("mine_identity", { targetLevel }),

  identities: () => invoke<IdentityList>("identities"),
  addIdentity: (nickname: string, label: string) =>
    invoke<IdentityList>("add_identity", { nickname, label }),
  setActiveIdentity: (fingerprint: string) =>
    invoke<IdentityList>("set_active_identity", { fingerprint }),
  setIdentityLabel: (fingerprint: string, label: string) =>
    invoke<IdentityList>("set_identity_label", { fingerprint, label }),
  removeIdentity: (fingerprint: string) =>
    invoke<IdentityList>("remove_identity", { fingerprint }),

  audioDevices: () => invoke<AudioDevices>("audio_devices"),

  settings: () => invoke<Settings>("settings"),
  setAudioSettings: (audio: AudioSettings) => invoke<void>("set_audio_settings", { audio }),
  setKeybinds: (keybinds: Keybinds) => invoke<BindingStatus[]>("set_keybinds", { keybinds }),
  keybindStatus: () => invoke<BindingStatus[]>("keybind_status"),
  mouseUdevRule: () => invoke<MouseAccess | null>("mouse_udev_rule"),

  // Runs the engine while disconnected so the audio tab has a live meter.
  startAudioPreview: () => invoke<void>("start_audio_preview"),
  stopAudioPreview: () => invoke<void>("stop_audio_preview"),

  connect: (request: ConnectRequest) => invoke<Connection>("connect", request),
  disconnect: (session: SessionId) => invoke<void>("disconnect", { session }),
  sessions: () => invoke<SessionList>("sessions"),

  // Voice lives on one connection at a time; this is the explicit move. Not
  // called on tab switch — reading one server should not cut you out of a
  // conversation on another.
  setVoiceSession: (session: SessionId) => invoke<void>("set_voice_session", { session }),

  joinChannel: (session: SessionId, channel: number) =>
    invoke<void>("join_channel", { session, channel }),
  leaveChannel: (session: SessionId) => invoke<void>("leave_channel", { session }),
  fetchHistory: (session: SessionId, channel: number) =>
    invoke<void>("fetch_history", { session, channel }),
  myPermissions: (session: SessionId) =>
    invoke<MyPermissions>("my_permissions", { session }),
  kick: (session: SessionId, clientId: number, reason?: string) =>
    invoke<void>("kick", { session, clientId, reason }),
  ban: (session: SessionId, fingerprint: string, reason: string, untilUnixMs?: number) =>
    invoke<void>("ban", { session, fingerprint, reason, untilUnixMs }),
  unban: (session: SessionId, fingerprint: string) =>
    invoke<void>("unban", { session, fingerprint }),
  listBans: (session: SessionId) => invoke<void>("list_bans", { session }),
  setServerMuted: (session: SessionId, clientId: number, muted: boolean) =>
    invoke<void>("set_server_muted", { session, clientId, muted }),
  moveUser: (session: SessionId, clientId: number, channel: number | null) =>
    invoke<void>("move_user", { session, clientId, channel }),
  moderationOptions: (session: SessionId, clientId: number) =>
    invoke<ModerationOptions>("moderation_options", { session, clientId }),
  createRole: (session: SessionId, name: string, permissions: Permission[]) =>
    invoke<void>("create_role", { session, name, permissions }),
  updateRole: (
    session: SessionId,
    roleId: number,
    /** `color: null` clears the tint; omitting leaves it untouched. */
    patch: { name?: string; color?: number | null; permissions?: Permission[] },
  ) =>
    invoke<void>("update_role", {
      session,
      roleId,
      name: patch.name,
      color: patch.color ?? undefined,
      clearColor: patch.color === null ? true : undefined,
      permissions: patch.permissions,
    }),
  deleteRole: (session: SessionId, roleId: number) =>
    invoke<void>("delete_role", { session, roleId }),
  reorderRoles: (session: SessionId, positions: [number, number][]) =>
    invoke<void>("reorder_roles", { session, positions }),
  setMemberRoles: (session: SessionId, fingerprint: string, roles: number[]) =>
    invoke<void>("set_member_roles", { session, fingerprint, roles }),
  setChannelOverwrite: (
    session: SessionId,
    channel: number,
    target: OverwriteTarget,
    allow: Permission[],
    deny: Permission[],
  ) => invoke<void>("set_channel_overwrite", { session, channel, target, allow, deny }),
  deleteChannelOverwrite: (session: SessionId, channel: number, target: OverwriteTarget) =>
    invoke<void>("delete_channel_overwrite", { session, channel, target }),
  channelOverwrites: (session: SessionId, channel: number) =>
    invoke<Overwrite[]>("channel_overwrites", { session, channel }),
  sendMessage: (session: SessionId, channel: number, content: string) =>
    invoke<void>("send_message", { session, channel, content }),

  setMuted: (muted: boolean) => invoke<VoiceState>("set_muted", { muted }),
  setDeafened: (deafened: boolean) => invoke<VoiceState>("set_deafened", { deafened }),
  setPushToTalkHeld: (held: boolean) => invoke<void>("set_push_to_talk_held", { held }),
  voiceState: () => invoke<VoiceState>("voice_state"),

  inputActivity: () => invoke<InputActivity>("input_activity"),
  speaking: () => invoke<Speaking>("speaking"),

  knownServers: () =>
    invoke<{ address: string; name: string; fingerprint: string }[]>("known_servers"),
  forgetServer: (address: string) => invoke<void>("forget_server", { address }),
  /** The deliberate re-pin after an identity change. Pass the fingerprint the
      user was shown — never whatever the server presents next. */
  trustChangedIdentity: (addressKey: string, fingerprint: string) =>
    invoke<void>("trust_changed_identity", { addressKey, fingerprint }),

  // Bookmarks are organisational; known servers above are security state. The
  // two are deliberately separate — see the Rust `bookmarks` module.
  bookmarks: () => invoke<Bookmark[]>("bookmarks"),
  addBookmark: (bookmark: BookmarkInput) => invoke<Bookmark[]>("add_bookmark", { bookmark }),
  updateBookmark: (id: number, bookmark: BookmarkInput) =>
    invoke<Bookmark[]>("update_bookmark", { id, bookmark }),
  removeBookmark: (id: number) => invoke<Bookmark[]>("remove_bookmark", { id }),

  // Every event names the connection it came from, so the app can route it to
  // the right tab rather than assuming there is only one.
  onServerEvent: (
    handler: (session: SessionId, event: ServerEvent) => void,
  ): Promise<UnlistenFn> =>
    listen<{ session: SessionId; event: ServerEvent }>("pickle:event", (e) =>
      handler(e.payload.session, e.payload.event),
    ),

  onMiningProgress: (handler: (progress: MiningProgress) => void): Promise<UnlistenFn> =>
    listen<MiningProgress>("pickle:mining", (e) => handler(e.payload)),

  // Voice state is pushed rather than tracked optimistically: a global shortcut
  // can change it while this window is not even focused.
  onVoiceState: (handler: (voice: VoiceState) => void): Promise<UnlistenFn> =>
    listen<VoiceState>("pickle:voice-state", (e) => handler(e.payload)),
};
