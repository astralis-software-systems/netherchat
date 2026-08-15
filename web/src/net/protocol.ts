// The Netherchat wire protocol, in TypeScript — a faithful transcription of the
// Go `protocol` package and PROTOCOL.md. The web client speaks this exact format
// to the UNCHANGED relay server; nothing here requires a server change.
//
// Binary fields (keys, nonces, ciphertext, signatures) travel as standard-base64
// strings, the way Go's encoding/json renders []byte. We keep them as strings in
// these wire types and convert at the crypto boundary (see client.ts).

export const PROTOCOL_VERSION = 3;

export const Op = {
  Hello: "hello",
  Welcome: "welcome",
  MemberJoined: "member_joined",
  MemberLeft: "member_left",
  KeyRequest: "key_request",
  KeyDeliver: "key_deliver",
  Message: "msg",
  Error: "error",
  // v2
  ServerMessage: "server_msg",
  Control: "control",
  ExecRequest: "exec_request",
  ExecResult: "exec_result",
  InviteRequest: "invite_request",
  InviteResult: "invite_result",
} as const;
export type Op = (typeof Op)[keyof typeof Op];

export const ActionVanish = "vanish";
export const ActionTTL = "ttl";

export interface Envelope {
  type: string;
  data?: unknown;
}

export interface WireMember {
  id: string;
  name: string;
  identity_key: string; // base64 Ed25519 public (32)
  kx_key: string; // base64 X25519 public (32)
}

export interface Hello {
  protocol_version: number;
  room: string;
  name: string;
  identity_key: string;
  kx_key: string;
  invite_token?: string;
}

export interface RoomPolicy {
  invite_only: boolean;
  webhook: boolean;
  ttl_seconds?: number;
}

export interface Welcome {
  protocol_version: number;
  your_id: string;
  room: string;
  members: WireMember[];
  you_are_first: boolean;
  policy: RoomPolicy;
}

export interface MemberJoined {
  member: WireMember;
}

export interface MemberLeft {
  id: string;
}

export interface KeyRequest {
  for_member: WireMember;
}

export interface KeyDeliver {
  to_id: string;
  from_id: string;
  epoch: number;
  nonce: string; // base64, 24 bytes
  wrapped_key: string; // base64 nacl/box
}

export interface WireMessage {
  from_id: string;
  epoch: number;
  nonce: string; // base64, 24 bytes
  ciphertext: string; // base64
  sig?: string; // base64 ed25519 over SigningBytes(...); absent = unsigned (v3, §3.3)
}

export interface WireError {
  code: string;
  message: string;
}

export interface ServerMessage {
  kind: string; // "webhook" | "system" | "exec"
  from: string;
  text: string;
  at: number; // unix seconds
}

export interface Control {
  action: string;
  by?: string;
  by_name?: string;
  ttl_seconds?: number;
}

export interface ExecRequest {
  command: string;
}

export interface ExecResult {
  command: string;
  allowed: boolean;
  output?: string;
  error?: string;
}

export type InviteRequest = Record<string, never>;

export interface InviteResult {
  room: string;
  token: string;
  expires?: number; // unix seconds, 0/absent = no expiry
}

/** Wrap a payload into an Envelope and JSON-encode it for the wire. */
export function encode(op: Op, payload: unknown): string {
  return JSON.stringify({ type: op, data: payload });
}

/** The relay a page talks to. */
export interface Relay {
  /** ws(s)://host/ws — the address the WebSocket opens. */
  url: string;
  /** host[:port] — shown in the UI, so a user can check it against the link they were sent. */
  host: string;
}

/**
 * The relay for a page: the origin that served it, and nothing else.
 *
 * There is deliberately no way to point the socket somewhere other than this
 * origin. The resolution reads the page URL's scheme and host only — the query
 * string is never consulted — so a crafted link cannot aim the connection at a
 * relay of the sender's choosing. That is not a theoretical concern: a hostile
 * relay is handed the room key by the ordinary key-exchange path (client.ts
 * `onKeyRequest` wraps it for any member the relay announces) while the status
 * line still reads "end-to-end encrypted".
 *
 * Cross-origin was never actually available anyway: the relay accepts WebSockets
 * with the library's default same-origin enforcement (server/internal/ws
 * `HandleWS`), so a genuine relay refuses a handshake from another origin. The
 * supported deployment serves this bundle and reverse-proxies `/ws` behind ONE
 * origin (see vite.config.ts and docs/commands.md).
 *
 * `url` and `host` are returned together so the endpoint the socket opens and the
 * endpoint the UI names cannot drift apart. `pageURL` is a parameter rather than a
 * read of `location` so the resolution is testable without a DOM.
 */
export function pageRelay(pageURL: string = location.href): Relay {
  const page = new URL(pageURL);
  const scheme = page.protocol === "https:" ? "wss:" : "ws:";
  return { url: `${scheme}//${page.host}/ws`, host: page.host };
}
