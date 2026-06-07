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

/** Normalize a user-entered server address to a ws(s):// URL ending in /ws. */
export function normalizeWsUrl(raw: string): string {
  let s = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    s = (location.protocol === "https:" ? "wss://" : "ws://") + s;
  }
  s = s.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");
  const u = new URL(s);
  if (u.pathname === "" || u.pathname === "/") u.pathname = "/ws";
  return u.toString();
}

/** The same-origin relay URL — the zero-config default for a self-hosted deploy. */
export function defaultWsUrl(): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/ws`;
}
