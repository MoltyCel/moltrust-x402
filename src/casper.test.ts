// Casper payers — before this, a non-EVM payer was dropped by extractWallet and
// the request passed the gate unscored, even with failBehavior: "closed".
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { checkAgent, extractPayment, extractWallet, __scoreCache } from "./core.js";

const EVM = "0x1111111111111111111111111111111111111111";
const ED25519 = "01" + "a".repeat(64);
const SECP256K1 = "02" + "b".repeat(66);
const ACCOUNT_HASH = "account-hash-" + "c".repeat(64);

/** An x402 payment header carrying an arbitrary decoded payload. */
function encode(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}

/** An x402 payment header carrying a payer in the top-level `from` field. */
function header(wallet: string): string {
  return encode({ from: wallet });
}

beforeEach(() => {
  __scoreCache.clear();
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

function mockFetchScore(score: number | null) {
  globalThis.fetch = vi.fn(async (url: unknown) =>
    score === null
      ? ({ ok: false, status: 503 } as Response)
      : ({
          ok: true,
          status: 200,
          json: async () => ({ wallet: String(url), score }),
        } as Response),
  ) as unknown as typeof fetch;
}

describe("extractWallet — Casper payers", () => {
  it("reads an ed25519 key from `from`", () => {
    expect(extractWallet(header(ED25519))).toBe(ED25519);
  });

  it("reads an ed25519 key from `payload.fromAddress`", () => {
    expect(extractWallet(encode({ payload: { fromAddress: ED25519 } }))).toBe(ED25519);
  });

  it("reads an ed25519 key from `payload.authorization.from`", () => {
    expect(extractWallet(encode({ payload: { authorization: { from: ED25519 } } }))).toBe(ED25519);
  });

  it("reads a secp256k1 key", () => {
    expect(extractWallet(header(SECP256K1))).toBe(SECP256K1);
  });

  it("reads an account hash and keeps its prefix", () => {
    expect(extractWallet(header(ACCOUNT_HASH))).toBe(ACCOUNT_HASH);
  });

  it("lower-cases a public key so one payer is one cache key", () => {
    expect(extractWallet(header(ED25519.toUpperCase()))).toBe(ED25519);
    expect(extractWallet(header("account-hash-" + "C".repeat(64)))).toBe(ACCOUNT_HASH);
  });

  it("accepts the v2 `x402 ` header prefix", () => {
    expect(extractWallet(`x402 ${header(ED25519)}`)).toBe(ED25519);
  });
});

describe("extractWallet — rejected payers", () => {
  const rejected: Array<[string, string]> = [
    ["an ed25519 key that is too short", "01" + "a".repeat(63)],
    ["an ed25519 key that is too long", "01" + "a".repeat(65)],
    ["a secp256k1 key of ed25519 length", "02" + "b".repeat(64)],
    ["an unknown 03 key tag", "03" + "a".repeat(64)],
    ["non-hex characters", "01" + "z".repeat(64)],
    ["a bare 64-hex string with no prefix", "a".repeat(64)],
    ["an account hash with a short tail", "account-hash-" + "c".repeat(63)],
    ["an EVM address of the wrong length", "0x1111"],
  ];

  for (const [name, value] of rejected) {
    it(`rejects ${name}`, () => {
      expect(extractWallet(header(value))).toBeNull();
    });
  }

  it("rejects a non-string payer", () => {
    expect(extractWallet(encode({ from: 12345 }))).toBeNull();
  });

  it("rejects a payload with no payer at all", () => {
    expect(extractWallet(encode({ network: "casper:casper" }))).toBeNull();
  });
});

describe("extractWallet — EVM regression", () => {
  it("still reads an EVM address from `from`", () => {
    expect(extractWallet(header(EVM))).toBe(EVM);
  });

  it("preserves EVM checksum casing", () => {
    const checksummed = "0xAbC1111111111111111111111111111111111111";
    expect(extractWallet(header(checksummed))).toBe(checksummed);
  });

  it("still returns null for junk and for no header", () => {
    expect(extractWallet("not base64 json")).toBeNull();
    expect(extractWallet(null)).toBeNull();
    expect(extractWallet(undefined)).toBeNull();
  });
});

describe("extractPayment — network hint", () => {
  it("reads casper:casper from the top level", () => {
    expect(extractPayment(encode({ from: ED25519, network: "casper:casper" }))).toEqual({
      wallet: ED25519,
      network: "casper:casper",
    });
  });

  it("reads casper:casper-test from the payload", () => {
    expect(
      extractPayment(encode({ payload: { fromAddress: ED25519, network: "casper:casper-test" } })),
    ).toEqual({ wallet: ED25519, network: "casper:casper-test" });
  });

  it("returns a null network when the payload declares none", () => {
    expect(extractPayment(header(EVM))).toEqual({ wallet: EVM, network: null });
  });
});

describe("checkAgent — Casper payers are gated, not waved through", () => {
  it("denies a low-scoring Casper payer instead of passing it through", async () => {
    mockFetchScore(10);
    const result = await checkAgent(encode({ from: ED25519, network: "casper:casper" }), {
      minScore: 60,
    });
    expect(result?.status).toBe(403);
    expect(result?.body.error).toBe("moltrust_score_too_low");
    expect(result?.body.wallet).toBe(ED25519);
    expect(result?.body.network).toBe("casper:casper");
  });

  it("denies a Casper payer when the registry is down (failBehavior defaults to closed)", async () => {
    mockFetchScore(null);
    const result = await checkAgent(header(ACCOUNT_HASH), { minScore: 60 });
    expect(result?.status).toBe(403);
    expect(result?.body.error).toBe("trust_api_unavailable");
    expect(result?.body.wallet).toBe(ACCOUNT_HASH);
  });

  it("allows a good Casper score", async () => {
    mockFetchScore(90);
    expect(await checkAgent(header(SECP256K1), { minScore: 60 })).toBeNull();
  });

  it("caches on the normalized payer, so casing does not cause a second lookup", async () => {
    mockFetchScore(90);
    await checkAgent(header(ED25519), { minScore: 60 });
    await checkAgent(header(ED25519.toUpperCase()), { minScore: 60 });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("looks the Casper payer up at the score endpoint unmodified", async () => {
    mockFetchScore(90);
    await checkAgent(header(ACCOUNT_HASH), { minScore: 60, apiUrl: "https://guard.test" });
    expect(globalThis.fetch).toHaveBeenCalledWith(
      `https://guard.test/api/agent/score-free/${ACCOUNT_HASH}`,
      expect.anything(),
    );
  });

  it("still passes through an unrecognized payer without a lookup", async () => {
    mockFetchScore(10);
    expect(await checkAgent(header("03" + "a".repeat(64)), { minScore: 60 })).toBeNull();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
