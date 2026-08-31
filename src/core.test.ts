// M7 — fail-closed by default, with a cache so a brief outage is not an outage.
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { checkAgent, __scoreCache } from "./core.js";

const WALLET = "0x1111111111111111111111111111111111111111";

/** An x402 payment header carrying a wallet. */
function header(wallet = WALLET): string {
  return Buffer.from(JSON.stringify({ from: wallet })).toString("base64");
}

beforeEach(() => {
  __scoreCache.clear();
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

function mockFetchScore(score: number | null) {
  globalThis.fetch = vi.fn(async () =>
    score === null
      ? ({ ok: false, status: 503 } as Response)
      : ({ ok: true, status: 200, json: async () => ({ wallet: WALLET, score }) } as Response),
  ) as unknown as typeof fetch;
}

describe("checkAgent fail behaviour", () => {
  it("denies when the registry is unreachable and nothing is cached", async () => {
    mockFetchScore(null);
    const result = await checkAgent(header(), { minScore: 60 });
    expect(result?.status).toBe(403);
    expect(result?.body.error).toBe("trust_api_unavailable");
  });

  it("still allows through when the integration opts out", async () => {
    mockFetchScore(null);
    const result = await checkAgent(header(), { minScore: 60, failBehavior: "open" });
    expect(result).toBeNull();
  });

  it("passes a good score", async () => {
    mockFetchScore(90);
    expect(await checkAgent(header(), { minScore: 60 })).toBeNull();
  });

  it("rejects a score below the threshold", async () => {
    mockFetchScore(10);
    const result = await checkAgent(header(), { minScore: 60 });
    expect(result?.status).toBe(403);
    expect(result?.body.error).toBe("moltrust_score_too_low");
  });

  it("ignores requests without a wallet", async () => {
    expect(await checkAgent(null, { minScore: 60 })).toBeNull();
  });
});

describe("cache", () => {
  it("serves a fresh score without a second lookup", async () => {
    mockFetchScore(90);
    await checkAgent(header(), { minScore: 60 });
    await checkAgent(header(), { minScore: 60 });
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("carries a brief outage on the cached score instead of denying", async () => {
    mockFetchScore(90);
    await checkAgent(header(), { minScore: 60, cacheTtlSeconds: 0 });

    mockFetchScore(null); // registry goes away
    const result = await checkAgent(header(), { minScore: 60, cacheTtlSeconds: 0 });
    expect(result).toBeNull();
  });

  it("still applies the threshold to a stale score", async () => {
    mockFetchScore(10);
    await checkAgent(header(), { minScore: 60, cacheTtlSeconds: 0 });

    mockFetchScore(null);
    const result = await checkAgent(header(), { minScore: 60, cacheTtlSeconds: 0 });
    expect(result?.status).toBe(403);
    expect(result?.body.error).toBe("moltrust_score_too_low");
  });

  it("denies once the grace window has passed", async () => {
    mockFetchScore(90);
    await checkAgent(header(), { minScore: 60 });

    mockFetchScore(null);
    const result = await checkAgent(header(), {
      minScore: 60,
      cacheTtlSeconds: 0,
      cacheStaleGraceSeconds: 0,
    });
    expect(result?.status).toBe(403);
    expect(result?.body.error).toBe("trust_api_unavailable");
  });
});
