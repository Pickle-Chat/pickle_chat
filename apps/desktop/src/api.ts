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
  fingerprint: string;
  securityLevel: number;
  channel: number | null;
  selfMuted: boolean;
  selfDeafened: boolean;
}

export interface Message {
  id: number;
  channel: number;
  authorNickname: string;
  authorFingerprint: string;
  content: string;
  sentAtUnixMs: number;
}

export interface Session {
  clientId: number;
  serverName: string;
  serverFingerprint: string;
  defaultChannel: number;
  channels: Channel[];
  users: User[];
}

export interface AudioDevice {
  name: string;
  isDefault: boolean;
  usable: boolean;
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

export type ServerEvent =
  | { type: "userJoined"; user: User }
  | { type: "userLeft"; clientId: number }
  | { type: "userMoved"; clientId: number; channel: number | null }
  | { type: "userUpdated"; user: User }
  | { type: "message"; message: Message }
  | { type: "typing"; clientId: number; channel: number }
  | { type: "serverError"; detail: string }
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

export interface Settings {
  audio: AudioSettings;
  keybinds: Keybinds;
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

/// Whether the system actually let us grab a key. Not every platform allows it
/// — see the note in the Rust `shortcuts` module.
export interface BindingStatus {
  action: KeybindAction;
  accelerator: string;
  registered: boolean;
  error: string | null;
}

export interface VoiceState {
  muted: boolean;
  deafened: boolean;
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

  // Runs the engine while disconnected so the audio tab has a live meter.
  startAudioPreview: () => invoke<void>("start_audio_preview"),
  stopAudioPreview: () => invoke<void>("stop_audio_preview"),

  connect: (request: ConnectRequest) => invoke<Session>("connect", request),
  disconnect: () => invoke<void>("disconnect"),

  joinChannel: (channel: number) => invoke<void>("join_channel", { channel }),
  sendMessage: (channel: number, content: string) =>
    invoke<void>("send_message", { channel, content }),

  setMuted: (muted: boolean) => invoke<VoiceState>("set_muted", { muted }),
  setDeafened: (deafened: boolean) => invoke<VoiceState>("set_deafened", { deafened }),
  setPushToTalkHeld: (held: boolean) => invoke<void>("set_push_to_talk_held", { held }),
  voiceState: () => invoke<VoiceState>("voice_state"),

  inputLevel: () => invoke<number>("input_level"),
  speaking: () => invoke<number[]>("speaking"),

  knownServers: () =>
    invoke<{ address: string; name: string; fingerprint: string }[]>("known_servers"),
  forgetServer: (address: string) => invoke<void>("forget_server", { address }),

  // Bookmarks are organisational; known servers above are security state. The
  // two are deliberately separate — see the Rust `bookmarks` module.
  bookmarks: () => invoke<Bookmark[]>("bookmarks"),
  addBookmark: (bookmark: BookmarkInput) => invoke<Bookmark[]>("add_bookmark", { bookmark }),
  updateBookmark: (id: number, bookmark: BookmarkInput) =>
    invoke<Bookmark[]>("update_bookmark", { id, bookmark }),
  removeBookmark: (id: number) => invoke<Bookmark[]>("remove_bookmark", { id }),

  onServerEvent: (handler: (event: ServerEvent) => void): Promise<UnlistenFn> =>
    listen<ServerEvent>("pickle:event", (e) => handler(e.payload)),

  onMiningProgress: (handler: (progress: MiningProgress) => void): Promise<UnlistenFn> =>
    listen<MiningProgress>("pickle:mining", (e) => handler(e.payload)),

  // Voice state is pushed rather than tracked optimistically: a global shortcut
  // can change it while this window is not even focused.
  onVoiceState: (handler: (voice: VoiceState) => void): Promise<UnlistenFn> =>
    listen<VoiceState>("pickle:voice-state", (e) => handler(e.payload)),
};
