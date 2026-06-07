// NetherClient — the browser port of tui/client. It owns ONE WebSocket scoped to
// ONE room (the connection==room model), runs the key-exchange state machine, and
// performs all encryption/decryption locally. The relay only ever sees ciphertext
// and sealed key blobs.
//
// The logic here mirrors tui/client/client.go deliberately, so behaviour matches
// the TUI exactly: the first member mints the epoch-0 key; later joiners receive
// it wrapped via nacl/box from the oldest member (the server-designated
// distributor); messages buffered before the key arrives are replayed once it
// does; /vanish ratchets every member's key forward deterministically.

import {
  Op,
  PROTOCOL_VERSION,
  ActionVanish,
  encode,
  type Envelope,
  type Hello,
  type Welcome,
  type MemberJoined,
  type MemberLeft,
  type KeyRequest,
  type KeyDeliver,
  type WireMessage,
  type WireError,
  type ServerMessage,
  type Control,
  type ExecResult,
  type InviteResult,
  type RoomPolicy,
} from "./protocol";
import { toB64, fromB64 } from "../crypto/base64";
import {
  newRoomKey,
  ratchet,
  wrapRoomKey,
  unwrapRoomKey,
  sealMessage,
  openMessage,
  type RoomKey,
} from "../crypto/group";
import type { Identity } from "../crypto/identity";

export type ClientEvent =
  | {
      t: "connected";
      selfID: string;
      youAreFirst: boolean;
      members: { id: string; name: string }[];
      policy: RoomPolicy;
    }
  | { t: "keyReady"; epoch: number }
  | { t: "message"; fromID: string; fromName: string; text: string; self: boolean; at: number }
  | { t: "serverMessage"; kind: string; from: string; text: string; at: number }
  | { t: "control"; action: string; byName?: string; self?: boolean; ttlSeconds?: number }
  | { t: "execResult"; command: string; allowed: boolean; output?: string; error?: string }
  | { t: "invite"; room: string; token: string; expires?: number }
  | { t: "memberJoined"; id: string; name: string }
  | { t: "memberLeft"; id: string; name: string }
  | { t: "error"; message: string }
  | { t: "disconnected"; reason?: string };

interface MemberRec {
  name: string;
  signPub: Uint8Array;
  kxPub: Uint8Array;
}

export class NetherClient {
  private ws?: WebSocket;
  private selfID = "";
  private members = new Map<string, MemberRec>();
  private rk: RoomKey | null = null;
  private pending: WireMessage[] = [];
  private closedByUser = false;

  constructor(
    private readonly url: string,
    private readonly room: string,
    private readonly name: string,
    private readonly id: Identity,
    private readonly onEvent: (e: ClientEvent) => void,
    private readonly inviteToken = "",
  ) {}

  connect(): void {
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.url);
    } catch (e) {
      this.onEvent({ t: "disconnected", reason: `could not open ${this.url}: ${String(e)}` });
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      const hello: Hello = {
        protocol_version: PROTOCOL_VERSION,
        room: this.room,
        name: this.name,
        identity_key: toB64(this.id.signPub),
        kx_key: toB64(this.id.kxPub),
      };
      if (this.inviteToken) hello.invite_token = this.inviteToken;
      this.sendRaw(encode(Op.Hello, hello));
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") this.handleRaw(ev.data);
    };
    ws.onclose = (ev) => {
      if (this.closedByUser) {
        this.onEvent({ t: "disconnected", reason: "closed" });
      } else {
        this.onEvent({ t: "disconnected", reason: ev.reason || `connection closed (code ${ev.code})` });
      }
    };
    // onerror is intentionally not surfaced separately: the browser always
    // follows it with onclose, which carries the user-facing reason.
  }

  // --- outbound API (mirrors tui/client) ---

  send(text: string): void {
    if (!this.rk) throw new Error("room key not established yet");
    const sealed = sealMessage(this.id, this.rk, this.room, this.selfID, new TextEncoder().encode(text));
    const msg: WireMessage = {
      from_id: this.selfID,
      epoch: this.rk.epoch,
      nonce: toB64(sealed.nonce),
      ciphertext: toB64(sealed.ciphertext),
      sig: toB64(sealed.signature),
    };
    this.sendRaw(encode(Op.Message, msg));
    // Local echo: the server fans the message out to OTHERS only.
    this.onEvent({ t: "message", fromID: this.selfID, fromName: this.name, text, self: true, at: Date.now() });
  }

  vanish(): void {
    this.ratchetForward();
    this.sendRaw(encode(Op.Control, { action: ActionVanish, by_name: this.name } satisfies Control));
    this.onEvent({ t: "control", action: ActionVanish, byName: this.name, self: true });
  }

  setTTL(seconds: number): void {
    this.sendRaw(encode(Op.Control, { action: "ttl", by_name: this.name, ttl_seconds: seconds } satisfies Control));
    this.onEvent({ t: "control", action: "ttl", byName: this.name, self: true, ttlSeconds: seconds });
  }

  requestInvite(): void {
    this.sendRaw(encode(Op.InviteRequest, {}));
  }

  exec(command: string): void {
    this.sendRaw(encode(Op.ExecRequest, { command }));
  }

  close(): void {
    this.closedByUser = true;
    this.ws?.close(1000, "bye");
  }

  fingerprintReady(): boolean {
    return this.rk !== null;
  }

  // --- inbound handling ---

  private handleRaw(raw: string): void {
    let env: Envelope;
    try {
      env = JSON.parse(raw) as Envelope;
    } catch {
      return;
    }
    switch (env.type) {
      case Op.Welcome:
        this.onWelcome(env.data as Welcome);
        break;
      case Op.MemberJoined:
        this.onMemberJoined(env.data as MemberJoined);
        break;
      case Op.MemberLeft:
        this.onMemberLeft(env.data as MemberLeft);
        break;
      case Op.KeyRequest:
        this.onKeyRequest(env.data as KeyRequest);
        break;
      case Op.KeyDeliver:
        this.onKeyDeliver(env.data as KeyDeliver);
        break;
      case Op.Message:
        this.processMessage(env.data as WireMessage);
        break;
      case Op.ServerMessage:
        this.onServerMessage(env.data as ServerMessage);
        break;
      case Op.Control:
        this.onControl(env.data as Control);
        break;
      case Op.ExecResult:
        this.onExecResult(env.data as ExecResult);
        break;
      case Op.InviteResult:
        this.onInviteResult(env.data as InviteResult);
        break;
      case Op.Error: {
        const e = env.data as WireError;
        this.onEvent({ t: "error", message: `server error [${e.code}]: ${e.message}` });
        break;
      }
    }
  }

  private onWelcome(w: Welcome): void {
    this.selfID = w.your_id;
    const members: { id: string; name: string }[] = [];
    for (const m of w.members) {
      this.addMember(m.id, m.name, m.identity_key, m.kx_key);
      members.push({ id: m.id, name: m.name });
    }
    let minted: RoomKey | null = null;
    if (w.you_are_first) {
      minted = newRoomKey(0);
      this.rk = minted;
    }
    this.onEvent({
      t: "connected",
      selfID: w.your_id,
      youAreFirst: w.you_are_first,
      members,
      policy: w.policy,
    });
    if (minted) this.onEvent({ t: "keyReady", epoch: minted.epoch });
  }

  private onMemberJoined(mj: MemberJoined): void {
    const m = mj.member;
    this.addMember(m.id, m.name, m.identity_key, m.kx_key);
    this.onEvent({ t: "memberJoined", id: m.id, name: m.name });
  }

  private onMemberLeft(ml: MemberLeft): void {
    const name = this.members.get(ml.id)?.name ?? ml.id;
    this.members.delete(ml.id);
    this.onEvent({ t: "memberLeft", id: ml.id, name });
  }

  // We were designated to wrap the current room key for a newly joined member.
  private onKeyRequest(kr: KeyRequest): void {
    if (!this.rk) {
      this.onEvent({ t: "error", message: "asked to distribute room key but we don't hold one" });
      return;
    }
    let recipientKX: Uint8Array;
    try {
      recipientKX = fromB64(kr.for_member.kx_key);
    } catch {
      this.onEvent({ t: "error", message: "bad recipient key" });
      return;
    }
    if (recipientKX.length !== 32) {
      this.onEvent({ t: "error", message: "bad recipient key length" });
      return;
    }
    const { nonce, wrapped } = wrapRoomKey(this.id, this.rk, recipientKX);
    const kd: KeyDeliver = {
      to_id: kr.for_member.id,
      from_id: "", // stamped authoritatively by the server
      epoch: this.rk.epoch,
      nonce: toB64(nonce),
      wrapped_key: toB64(wrapped),
    };
    this.sendRaw(encode(Op.KeyDeliver, kd));
  }

  // An existing member wrapped the room key for us.
  private onKeyDeliver(kd: KeyDeliver): void {
    const sender = this.members.get(kd.from_id);
    if (!sender) {
      this.onEvent({ t: "error", message: `room key from unknown member ${kd.from_id}` });
      return;
    }
    let rk: RoomKey;
    try {
      rk = unwrapRoomKey(this.id, kd.epoch, fromB64(kd.nonce), fromB64(kd.wrapped_key), sender.kxPub);
    } catch (e) {
      this.onEvent({ t: "error", message: `unwrap room key: ${String(e)}` });
      return;
    }
    this.rk = rk;
    const pending = this.pending;
    this.pending = [];
    this.onEvent({ t: "keyReady", epoch: rk.epoch });
    for (const m of pending) this.processMessage(m);
  }

  private processMessage(m: WireMessage): void {
    if (!this.rk) {
      // Key not established yet — buffer and replay once it arrives.
      this.pending.push(m);
      return;
    }
    if (m.from_id === this.selfID) return; // never our own echo (server excludes us)
    const sender = this.members.get(m.from_id);
    if (!sender) {
      this.onEvent({ t: "error", message: `message from unknown member ${m.from_id}` });
      return;
    }
    let pt: Uint8Array;
    try {
      pt = openMessage(
        this.rk,
        sender.signPub,
        this.room,
        m.from_id,
        m.epoch,
        fromB64(m.nonce),
        fromB64(m.ciphertext),
        m.sig ? fromB64(m.sig) : new Uint8Array(0),
      );
    } catch (e) {
      this.onEvent({ t: "error", message: `decrypt from ${sender.name}: ${String(e)}` });
      return;
    }
    this.onEvent({
      t: "message",
      fromID: m.from_id,
      fromName: sender.name,
      text: new TextDecoder().decode(pt),
      self: false,
      at: Date.now(),
    });
  }

  private onServerMessage(sm: ServerMessage): void {
    const at = sm.at > 0 ? sm.at * 1000 : Date.now();
    this.onEvent({ t: "serverMessage", kind: sm.kind, from: sm.from, text: sm.text, at });
  }

  private onControl(ctrl: Control): void {
    if (ctrl.action === ActionVanish) {
      // Everyone advances deterministically; no key exchange needed.
      this.ratchetForward();
    }
    this.onEvent({ t: "control", action: ctrl.action, byName: ctrl.by_name, ttlSeconds: ctrl.ttl_seconds });
  }

  private onExecResult(r: ExecResult): void {
    this.onEvent({ t: "execResult", command: r.command, allowed: r.allowed, output: r.output, error: r.error });
  }

  private onInviteResult(r: InviteResult): void {
    this.onEvent({ t: "invite", room: r.room, token: r.token, expires: r.expires });
  }

  // --- internal ---

  private ratchetForward(): void {
    if (this.rk) this.rk = ratchet(this.rk);
  }

  private addMember(id: string, name: string, identityKeyB64: string, kxKeyB64: string): void {
    try {
      const signPub = fromB64(identityKeyB64);
      const kxPub = fromB64(kxKeyB64);
      if (signPub.length !== 32 || kxPub.length !== 32) return; // skip malformed
      this.members.set(id, { name, signPub, kxPub });
    } catch {
      // skip malformed
    }
  }

  private sendRaw(s: string): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(s);
  }
}
