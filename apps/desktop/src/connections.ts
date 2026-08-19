// Per-connection UI state.
//
// A reducer rather than several `useState` maps: every server event mutates one
// connection's slice, and keeping the rules in one place is what stops the tabs
// from drifting apart as they are added.

import type { Connection, Message, ServerEvent, Session, SessionId, User } from "./api";

export interface ConnectionState {
  session: SessionId;
  info: Session;
  identity: string;
  users: User[];
  messages: Message[];
  activeChannel: number | null;
  /// Set when the server drops us. The tab stays so the reason is readable
  /// rather than vanishing along with the explanation.
  disconnected: string | null;
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
            users: info.users,
            messages: [],
            activeChannel: info.defaultChannel,
            disconnected: null,
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

    case "serverError":
      return { ...connection, disconnected: connection.disconnected ?? event.detail };

    case "disconnected":
      // The tab is kept, holding the reason. Removing it here would take the
      // explanation away at the moment it becomes relevant.
      return { ...connection, disconnected: event.reason, users: [] };

    case "typing":
      return connection;
  }
}
