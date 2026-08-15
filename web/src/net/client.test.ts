// Does signed-ness survive the trip from the crypto to the structure the UI
// consumes? group.ts computes it, client.ts must carry it into ClientEvent, and
// join/main.ts renders from that event. This file covers the first two hops.
//
// The render hop is NOT covered here, and deliberately not faked: vitest runs in
// the node environment (no `test` block in vite.config.ts) and web/ has no jsdom
// or happy-dom dependency, so there is no document to append a row to. A test
// that stubbed one would assert against the stub, not the browser. What is
// testable — and what actually regresses if someone drops the flag — is the
// event the renderer reads, so that is what is pinned below.
//
// The relay is replaced by a fake socket rather than mocked at the crypto layer:
// the point is that a real Go-shaped frame with its `sig` removed still reaches
// the UI flagged as unsigned, which is exactly the relay-downgrade path.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { NetherClient, type ClientEvent } from "./client";
import { Op, type KeyDeliver, type Welcome, type WireMessage } from "./protocol";
import { newRoomKey, sealMessage, wrapRoomKey, type RoomKey } from "../crypto/group";
import { newEphemeralIdentity, type Identity } from "../crypto/identity";
import { toB64, fromB64 } from "../crypto/base64";

const ROOM = "ops";
const SELF_ID = "me-0001";
const PEER_ID = "alice-9f3c";

/** Minimal stand-in for the browser WebSocket: records sends, replays inbound. */
class FakeSocket {
  static readonly OPEN = 1;
  readyState = FakeSocket.OPEN;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number; reason: string }) => void) | null = null;

  constructor(readonly url: string) {
    lastSocket = this;
  }
  send(s: string): void {
    this.sent.push(s);
  }
  close(): void {}

  /** Push one server frame at the client, the way onmessage would. */
  deliver(type: string, data: unknown): void {
    this.onmessage?.({ data: JSON.stringify({ type, data }) });
  }
}

let lastSocket: FakeSocket | undefined;
let realWebSocket: unknown;

beforeEach(() => {
  realWebSocket = (globalThis as Record<string, unknown>).WebSocket;
  (globalThis as Record<string, unknown>).WebSocket = FakeSocket;
  lastSocket = undefined;
});

afterEach(() => {
  (globalThis as Record<string, unknown>).WebSocket = realWebSocket;
});

interface Room {
  client: NetherClient;
  events: ClientEvent[];
  socket: FakeSocket;
  peer: Identity;
  rk: RoomKey;
}

/**
 * Bring a client to the point where it holds the room key: connect, hand it a
 * Welcome naming one existing member, then have that member wrap the room key
 * for it — the ordinary second-joiner path from client.go.
 */
function joinedRoom(): Room {
  const me = newEphemeralIdentity();
  const peer = newEphemeralIdentity();
  const events: ClientEvent[] = [];

  const client = new NetherClient("ws://relay.test/ws", ROOM, "me", me, (e) => events.push(e));
  client.connect();
  const socket = lastSocket!;

  socket.deliver(Op.Welcome, {
    protocol_version: 3,
    your_id: SELF_ID,
    room: ROOM,
    members: [
      { id: PEER_ID, name: "alice", identity_key: toB64(peer.signPub), kx_key: toB64(peer.kxPub) },
    ],
    you_are_first: false,
    policy: { invite_only: false, webhook: false },
  } satisfies Welcome);

  const rk = newRoomKey(0);
  const { nonce, wrapped } = wrapRoomKey(peer, rk, me.kxPub);
  socket.deliver(Op.KeyDeliver, {
    to_id: SELF_ID,
    from_id: PEER_ID,
    epoch: rk.epoch,
    nonce: toB64(nonce),
    wrapped_key: toB64(wrapped),
  } satisfies KeyDeliver);

  return { client, events, socket, peer, rk };
}

/** A wire frame from the peer. `strip` drops `sig`, as a hostile relay would. */
function peerFrame(peer: Identity, rk: RoomKey, text: string, strip = false): WireMessage {
  const sealed = sealMessage(peer, rk, ROOM, PEER_ID, new TextEncoder().encode(text));
  return {
    from_id: PEER_ID,
    epoch: rk.epoch,
    nonce: toB64(sealed.nonce),
    ciphertext: toB64(sealed.ciphertext),
    sig: strip ? "" : toB64(sealed.signature),
  };
}

function messages(events: ClientEvent[]) {
  return events.filter((e): e is Extract<ClientEvent, { t: "message" }> => e.t === "message");
}

describe("signed-ness reaches the UI layer", () => {
  it("establishes the room key (harness sanity)", () => {
    const { events } = joinedRoom();
    expect(events.some((e) => e.t === "keyReady")).toBe(true);
  });

  it("flags a signed message as signed", () => {
    const { socket, events, peer, rk } = joinedRoom();
    socket.deliver(Op.Message, peerFrame(peer, rk, "the database is on fire"));

    const msgs = messages(events);
    expect(msgs).toHaveLength(1);
    expect(msgs[0].text).toBe("the database is on fire");
    expect(msgs[0].signed).toBe(true);
  });

  it("flags a relay-stripped signature as unsigned, but still delivers it", () => {
    const { socket, events, peer, rk } = joinedRoom();
    socket.deliver(Op.Message, peerFrame(peer, rk, "trust me", true));

    const msgs = messages(events);
    // Still accepted — v2 interop is unchanged; what changes is that we say so.
    expect(msgs).toHaveLength(1);
    expect(msgs[0].text).toBe("trust me");
    expect(msgs[0].signed).toBe(false);
  });

  it("keeps the flag per message, not per sender", () => {
    const { socket, events, peer, rk } = joinedRoom();
    socket.deliver(Op.Message, peerFrame(peer, rk, "one"));
    socket.deliver(Op.Message, peerFrame(peer, rk, "two", true));
    socket.deliver(Op.Message, peerFrame(peer, rk, "three"));

    expect(messages(events).map((m) => [m.text, m.signed])).toEqual([
      ["one", true],
      ["two", false],
      ["three", true],
    ]);
  });

  it("marks our own echo signed (we always sign what we send)", () => {
    const { client, events } = joinedRoom();
    client.send("deploy done");

    const mine = messages(events).filter((m) => m.self);
    expect(mine).toHaveLength(1);
    expect(mine[0].signed).toBe(true);
  });

  it("rejects an INVALID signature outright instead of showing it unsigned", () => {
    const { socket, events, peer, rk } = joinedRoom();
    const frame = peerFrame(peer, rk, "forged");
    const sig = fromB64(frame.sig!);
    sig[0] ^= 0x01;
    frame.sig = toB64(sig);
    socket.deliver(Op.Message, frame);

    // No message event at all: the body must never reach the DOM, and it must
    // not be laundered into the "unsigned" bucket either.
    expect(messages(events)).toHaveLength(0);
    expect(events.filter((e) => e.t === "error")).toHaveLength(1);
  });

  it("carries the flag through messages buffered before the key arrived", () => {
    // Frames that land before KeyDeliver are queued and replayed; the replay
    // path must not lose signed-ness the way the direct path used to.
    const me = newEphemeralIdentity();
    const peer = newEphemeralIdentity();
    const events: ClientEvent[] = [];
    const client = new NetherClient("ws://relay.test/ws", ROOM, "me", me, (e) => events.push(e));
    client.connect();
    const socket = lastSocket!;

    socket.deliver(Op.Welcome, {
      protocol_version: 3,
      your_id: SELF_ID,
      room: ROOM,
      members: [
        { id: PEER_ID, name: "alice", identity_key: toB64(peer.signPub), kx_key: toB64(peer.kxPub) },
      ],
      you_are_first: false,
      policy: { invite_only: false, webhook: false },
    } satisfies Welcome);

    const rk = newRoomKey(0);
    socket.deliver(Op.Message, peerFrame(peer, rk, "early signed"));
    socket.deliver(Op.Message, peerFrame(peer, rk, "early stripped", true));
    expect(messages(events)).toHaveLength(0); // buffered, no key yet

    const { nonce, wrapped } = wrapRoomKey(peer, rk, me.kxPub);
    socket.deliver(Op.KeyDeliver, {
      to_id: SELF_ID,
      from_id: PEER_ID,
      epoch: rk.epoch,
      nonce: toB64(nonce),
      wrapped_key: toB64(wrapped),
    } satisfies KeyDeliver);

    expect(messages(events).map((m) => [m.text, m.signed])).toEqual([
      ["early signed", true],
      ["early stripped", false],
    ]);
  });
});
