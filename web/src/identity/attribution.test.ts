import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  identityDisplayFor,
  identityDisplayMark,
  identityDisplayLabel,
  type IdentityDisplayState,
} from "./attribution";

// D-I, checked against the Go implementation rather than against a reading of
// it. testdata/attribution.json is written by tui/e2e/attribution_vectors_test.go
// (`GEN_INTEROP=1 go test ./tui/e2e -run TestGenAttributionVectors -v`) and an
// ungated Go test keeps it matching that build, so a change to the rule on
// either side fails on the other.
//
// Each case carries TWO expected outcomes. `withNoIssuerPinned` is the one this
// file checks, because it is the only one a browser can ever be in: verification
// takes an issuer public key and an evaluation time, and a page served from a
// join link has neither. `withIssuerPinned` is in the file so the asymmetry is
// visible where the rule lives, and so the Go side has something to check.

interface Outcome {
  state: IdentityDisplayState;
  name: string;
  mark: string;
}

interface VectorCase {
  name: string;
  why: string;
  assertedName: string;
  subjectFingerprint: string;
  attestationB64: string;
  withIssuerPinned: Outcome;
  withNoIssuerPinned: Outcome;
}

interface VectorFile {
  issuerKeyB64: string;
  evaluatedAt: string;
  cases: VectorCase[];
}

function vectors(): VectorFile {
  const path = fileURLToPath(new URL("../net/testdata/attribution.json", import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as VectorFile;
}

function render(c: VectorCase) {
  return identityDisplayFor(c.assertedName, c.subjectFingerprint, c.attestationB64 || undefined);
}

describe("D-I attribution vectors", () => {
  it("has the cases both implementations were written against", () => {
    const v = vectors();
    expect(v.cases.length).toBeGreaterThanOrEqual(6);
    expect(v.cases.map((c) => c.name)).toContain("attested_no_display_name");
    expect(v.cases.map((c) => c.name)).toContain("credential_about_another_key");
  });

  it("agrees with Go on every case, as the reader a browser actually is", () => {
    for (const c of vectors().cases) {
      const got = render(c);
      expect({ state: got.state, name: got.name, mark: identityDisplayMark(got.state) }, c.name).toEqual(
        c.withNoIssuerPinned,
      );
    }
  });

  it("cannot reach a verified state from any input in the file", () => {
    // The stronger form of the claim above. Two of these cases DO verify for a
    // reader holding the issuer key — the file says so — and this client renders
    // none of them as verified, because it is not that reader and cannot become
    // one.
    const verifiable = vectors().cases.filter((c) => c.withIssuerPinned.mark === "◆");
    expect(verifiable.length).toBeGreaterThanOrEqual(2);
    for (const c of verifiable) {
      const got = render(c);
      expect(got.state, c.name).toBe("carried");
      expect(got.name, c.name).toBe(c.assertedName);
      expect(identityDisplayMark(got.state), c.name).toBe("◇");
    }
  });

  it("never renders a credential's display_name where the person's name goes", () => {
    // The failure this decision exists to prevent, stated directly: a self-issued
    // artifact claiming "Chief Executive" must not put those words on a roster.
    const c = vectors().cases.find((x) => x.name === "carried_signed_by_an_unpinned_authority");
    expect(c).toBeDefined();
    const got = render(c!);
    expect(got.name).toBe(c!.assertedName);
    expect(got.displayName).toBe("Chief Executive"); // available…
    expect(got.name).not.toBe("Chief Executive"); // …and not the name on screen
  });

  it("notices a credential that is about a different key — the one check it CAN make", () => {
    const c = vectors().cases.find((x) => x.name === "credential_about_another_key");
    expect(c).toBeDefined();
    const got = render(c!);
    expect(got.subjectMismatch).toBe(true);
    expect(identityDisplayLabel(got)).toContain("DIFFERENT key");

    // And the control, so the check is not simply always true: the same shape of
    // artifact on the key it is actually about.
    const own = vectors().cases.find((x) => x.name === "attested_with_display_name")!;
    expect(render(own).subjectMismatch).toBe(false);
  });
});

describe("attribution, on its own terms", () => {
  it("treats no credential as the asserted state and marks it with nothing", () => {
    const got = identityDisplayFor("alice", "SHA256:a", undefined);
    expect(got.state).toBe("asserted");
    expect(identityDisplayMark(got.state)).toBe("");
    expect(got.name).toBe("alice");
    expect(got.subjectMismatch).toBe(false);
  });

  it("treats an empty string as no credential", () => {
    expect(identityDisplayFor("alice", "SHA256:a", "").state).toBe("asserted");
  });

  it("treats unreadable bytes as carried, not as nothing", () => {
    for (const bad of [btoa("{not json"), "!!!not base64!!!", btoa("[]"), btoa("null")]) {
      const got = identityDisplayFor("dave", "SHA256:d", bad);
      expect(got.state, bad).toBe("carried");
      expect(got.name, bad).toBe("dave");
      expect(got.detail, bad).not.toBe("");
    }
  });

  it("treats a caller that named no key as a mismatch, never as a match", () => {
    const artifact = btoa(JSON.stringify({ subject: "SHA256:m", principal: "ceo@acme.example" }));
    expect(identityDisplayFor("mallory", "", artifact).subjectMismatch).toBe(true);
  });

  it("carries the words beside the mark, for a reader who cannot see a glyph", () => {
    const artifact = btoa(
      JSON.stringify({ subject: "SHA256:m", principal: "ceo@acme.example", issuer: "SHA256:zzz" }),
    );
    const label = identityDisplayLabel(identityDisplayFor("mallory", "SHA256:m", artifact));
    expect(label).toContain("ceo@acme.example");
    expect(label).toContain("not checked here");
    expect(identityDisplayLabel(identityDisplayFor("alice", "SHA256:a", undefined))).toContain("not proven");
  });
});
