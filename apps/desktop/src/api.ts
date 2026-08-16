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

// The index signature is what `invoke` requires of its argument object; the
// named fields are what actually keeps call sites honest.
export interface ConnectRequest {
  [key: string]: unknown;
  address: string;
  password?: string;
  inputDevice?: string;
  outputDevice?: string;
  pushToTalk: boolean;
}

export const api = {
  identityInfo: () => invoke<Identity>("identity_info"),
  setNickname: (nickname: string) => invoke<Identity>("set_nickname", { nickname }),
  mineIdentity: (targetLevel: number) => invoke<void>("mine_identity", { targetLevel }),

  audioDevices: () => invoke<AudioDevices>("audio_devices"),

  connect: (request: ConnectRequest) => invoke<Session>("connect", request),
  disconnect: () => invoke<void>("disconnect"),

  joinChannel: (channel: number) => invoke<void>("join_channel", { channel }),
  sendMessage: (channel: number, content: string) =>
    invoke<void>("send_message", { channel, content }),

  setMuted: (muted: boolean) => invoke<void>("set_muted", { muted }),
  setDeafened: (deafened: boolean) => invoke<void>("set_deafened", { deafened }),
  setPushToTalkHeld: (held: boolean) => invoke<void>("set_push_to_talk_held", { held }),

  inputLevel: () => invoke<number>("input_level"),
  speaking: () => invoke<number[]>("speaking"),

  knownServers: () =>
    invoke<{ address: string; name: string; fingerprint: string }[]>("known_servers"),
  forgetServer: (address: string) => invoke<void>("forget_server", { address }),

  onServerEvent: (handler: (event: ServerEvent) => void): Promise<UnlistenFn> =>
    listen<ServerEvent>("pickle:event", (e) => handler(e.payload)),

  onMiningProgress: (handler: (progress: MiningProgress) => void): Promise<UnlistenFn> =>
    listen<MiningProgress>("pickle:mining", (e) => handler(e.payload)),
};
