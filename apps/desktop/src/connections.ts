// Per-connection UI state.
//
// A reducer rather than several `useState` maps: every server event mutates one
// connection's slice, and keeping the rules in one place is what stops the tabs
// from drifting apart as they are added.

import type {
  Channel,
  Connection,
  Message,
  ServerErrorCode,
  ServerEvent,
  Session,
  SessionId,
  User,
} from "./api";

export interface ConnectionState {
  session: SessionId;
  info: Session;
  identity: string;
  /// The live channel list, seeded from the login snapshot exactly as `users`
  /// is. `info.channels` stays what login said; this one follows the channel
  /// events, which is what lets the server change the map mid-session.
  channels: Channel[];
  users: User[];
  messages: Message[];
  activeChannel: number | null;
  /// Set when the server drops us. The tab stays so the reason is readable
  /// rather than vanishing along with the explanation.
  disconnected: string | null;
  /// The latest refusal, shown as a dismissible banner inside this tab. One
  /// slot, last wins: a refusal answers the user's most recent action, and a
  /// stack of stale ones would bury the answer. Deliberately NOT fatal — a
  /// server saying "no" is a conversation, not a disconnection.
  notice: { code: ServerErrorCode; detail: string } | null;
  /// Cleared when the tab is looked at, so a tab you are reading never nags.
  unread: number;
}

export interface ConnectionsState {
  order: SessionId[];
  byId: Record<SessionId, ConnectionState>;
  /// Which tab is being looked at. `null` means the connect form.
  active: SessionId | null;
}

export const EMPTY: ConnectionsState = { order: [], byId: {}, active: null };

export type Action =
  | { type: "opened"; connection: Connection }
  | { type: "closed"; session: SessionId }
  | { type: "focused"; session: SessionId | null }
  | { type: "channelSelected"; session: SessionId; channel: number | null }
  | { type: "noticeDismissed"; session: SessionId }
  | { type: "event"; session: SessionId; event: ServerEvent };

export function reduce(state: ConnectionsState, action: Action): ConnectionsState {
  switch (action.type) {
    case "opened": {
      const { session, info, identity } = action.connection;
      return {
        // Reconnecting an id that is somehow already present replaces it rather
        // than listing the same connection twice.
        order: state.order.includes(session) ? state.order : [...state.order, session],
        byId: {
          ...state.byId,
          [session]: {
            session,
            info,
            identity,
            channels: info.channels,
            users: info.users,
            messages: [],
            activeChannel: info.defaultChannel,
            disconnected: null,
            notice: null,
            unread: 0,
          },
        },
        active: session,
      };
    }

    case "closed": {
      const order = state.order.filter((id) => id !== action.session);
      const byId = { ...state.byId };
      delete byId[action.session];
      return {
        order,
        byId,
        // Falls back to a neighbouring tab rather than the connect form, so
        // closing one of several connections does not feel like leaving them
        // all.
        active: state.active === action.session ? (order[order.length - 1] ?? null) : state.active,
      };
    }

    case "focused":
      return {
        ...state,
        active: action.session,
        byId:
          action.session === null
            ? state.byId
            : patch(state, action.session, (c) => ({ ...c, unread: 0 })),
      };

    case "channelSelected":
      return {
        ...state,
        byId: patch(state, action.session, (c) => ({ ...c, activeChannel: action.channel })),
      };

    case "noticeDismissed":
      return {
        ...state,
        byId: patch(state, action.session, (c) => ({ ...c, notice: null })),
      };

    case "event":
      return {
        ...state,
        byId: patch(state, action.session, (c) => applyEvent(c, action.event, state.active)),
      };
  }
}

/// Update one connection, leaving the rest untouched.
///
/// An event for a connection that is already gone is dropped: it raced a
/// disconnect, and resurrecting a closed tab would be worse than losing it.
function patch(
  state: ConnectionsState,
  session: SessionId,
  f: (connection: ConnectionState) => ConnectionState,
): Record<SessionId, ConnectionState> {
  const existing = state.byId[session];
  if (!existing) return state.byId;
  return { ...state.byId, [session]: f(existing) };
}

function applyEvent(
  connection: ConnectionState,
  event: ServerEvent,
  active: SessionId | null,
): ConnectionState {
  switch (event.type) {
    case "userJoined":
      return {
        ...connection,
        users: [
          ...connection.users.filter((u) => u.clientId !== event.user.clientId),
          event.user,
        ],
      };

    case "userLeft":
      return {
        ...connection,
        users: connection.users.filter((u) => u.clientId !== event.clientId),
      };

    case "userMoved":
      return {
        ...connection,
        users: connection.users.map((u) =>
          u.clientId === event.clientId ? { ...u, channel: event.channel } : u,
        ),
      };

    case "userUpdated":
      return {
        ...connection,
        users: connection.users.map((u) =>
          u.clientId === event.user.clientId ? event.user : u,
        ),
      };

    case "message":
      return {
        ...connection,
        messages: [...connection.messages, event.message],
        // Only counts against a tab you are not looking at.
        unread:
          active === connection.session ? connection.unread : connection.unread + 1,
      };

    case "history": {
      // The past merges in rather than replacing: live messages may already
      // have arrived for this channel, and the author's own echo may overlap
      // with what the server hands back. Ids are server-assigned and global,
      // so they are both the dedupe key and the sort order. Unread does not
      // move — nothing here is new.
      const byId = new Map(connection.messages.map((m) => [m.id, m]));
      for (const message of event.messages) byId.set(message.id, message);
      return {
        ...connection,
        messages: [...byId.values()].sort((a, b) => a.id - b.id),
      };
    }

    // The channel map can now change mid-session. Same shapes as the user
    // events: created doubles as an upsert, updated replaces by id.
    case "channelCreated":
      return {
        ...connection,
        channels: [
          ...connection.channels.filter((c) => c.id !== event.channel.id),
          event.channel,
        ],
      };

    case "channelUpdated":
      return {
        ...connection,
        channels: connection.channels.map((c) =>
          c.id === event.channel.id ? event.channel : c,
        ),
      };

    case "channelRemoved": {
      const channels = connection.channels.filter((c) => c.id !== event.channelId);
      // The view cannot stay on a channel that no longer exists for us. Fall
      // back to the login suggestion if it survives, else to nowhere.
      const activeChannel =
        connection.activeChannel === event.channelId
          ? channels.some((c) => c.id === connection.info.defaultChannel)
            ? connection.info.defaultChannel
            : null
          : connection.activeChannel;
      return { ...connection, channels, activeChannel };
    }

    // A refusal is an answer, not an outage: the tab stays alive and the
    // reason lands next to whatever provoked it. Only the `disconnected`
    // event — which the client core emits exactly when the control stream is
    // genuinely gone — may declare this connection dead.
    case "serverError":
      return { ...connection, notice: { code: event.code, detail: event.detail } };

    case "disconnected":
      // The tab is kept, holding the reason. Removing it here would take the
      // explanation away at the moment it becomes relevant.
      return { ...connection, disconnected: event.reason, users: [] };

    case "typing":
      return connection;
  }
}
