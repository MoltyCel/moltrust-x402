export interface MoltrustGuardOptions {
  /** Minimum MoltGuard score to allow (0-100). Default: 50 */
  minScore?: number;
  /** MoltGuard API base URL. Default: https://api.moltrust.ch/guard */
  apiUrl?: string;
  /** Timeout in ms for the score lookup. Default: 3000 */
  timeout?: number;
  /**
   * Behavior when MolTrust API is unreachable. Default: 'closed' as of 0.2.0.
   * A gate that opens when the registry is down is not a gate. Set to 'open'
   * per integration to restore the previous behaviour.
   */
  failBehavior?: "open" | "closed";
  /** Seconds a successful score is reused without a lookup. Default: 60 */
  cacheTtlSeconds?: number;
  /**
   * Seconds a cached score stays usable after a FAILED lookup. Default: 300.
   * This is what keeps a short registry outage from denying every request.
   */
  cacheStaleGraceSeconds?: number;
}

export interface MoltGuardScore {
  wallet: string;
  score: number;
  _meta?: Record<string, unknown>;
}

export interface MoltGuardResult {
  wallet: string;
  score: number | null;
  protocol: string;
  failOpen?: boolean;
}

const DEFAULT_API = "https://api.moltrust.ch/guard";
const DEFAULT_MIN_SCORE = 50;
const DEFAULT_TIMEOUT = 3000;

/**
 * Extract wallet address from x402 payment header.
 *
 * Supports both:
 * - v2: PAYMENT-SIGNATURE header (base64 JSON with payload.fromAddress)
 * - v1: X-PAYMENT header (same format, backward compat)
 */
export function extractWallet(paymentHeader: string | null | undefined): string | null {
  if (!paymentHeader) return null;
  try {
    const raw = paymentHeader.startsWith("x402 ") ? paymentHeader.slice(5) : paymentHeader;
    const decoded = JSON.parse(Buffer.from(raw, "base64").toString());
    const addr: string | undefined =
      decoded?.payload?.fromAddress ??
      decoded?.fromAddress ??
      decoded?.payload?.authorization?.from ??
      decoded?.from;
    if (addr && /^0x[0-9a-fA-F]{40}$/.test(addr)) return addr;
    return null;
  } catch {
    return null;
  }
}

/** Fetch agent score from MoltGuard. Returns null on any failure. */
export async function fetchScore(
  wallet: string,
  opts: MoltrustGuardOptions
): Promise<MoltGuardScore | null> {
  const base = (opts.apiUrl ?? DEFAULT_API).replace(/\/+$/, "");
  const url = `${base}/api/agent/score-free/${wallet}`;
  const timeout = opts.timeout ?? DEFAULT_TIMEOUT;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as MoltGuardScore;
  } catch {
    return null;
  }
}

/**
 * Per-process cache of successful score lookups.
 *
 * Two windows: inside the TTL the score is reused with no network call; between
 * the TTL and the grace window it is still usable, but only after a live lookup
 * has failed. Bounded so a stream of unknown wallets cannot grow the process.
 */
const CACHE_MAX_ENTRIES = 1024;

const scoreCache = {
  entries: new Map<string, { score: number; storedAt: number }>(),

  put(wallet: string, score: number): void {
    if (this.entries.size >= CACHE_MAX_ENTRIES && !this.entries.has(wallet)) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(wallet, { score, storedAt: Date.now() });
  },

  getFresh(wallet: string, ttlMs: number): number | undefined {
    if (ttlMs <= 0) return undefined; // always look up live
    const entry = this.entries.get(wallet);
    if (!entry) return undefined;
    return Date.now() - entry.storedAt <= ttlMs ? entry.score : undefined;
  },

  getStale(wallet: string, graceMs: number): number | undefined {
    if (graceMs <= 0) return undefined; // grace disabled
    const entry = this.entries.get(wallet);
    if (!entry) return undefined;
    if (Date.now() - entry.storedAt <= graceMs) return entry.score;
    this.entries.delete(wallet);
    return undefined;
  },

  clear(): void {
    this.entries.clear();
  },
};

/** Exposed for tests. */
export const __scoreCache = scoreCache;

function applyThreshold(
  wallet: string,
  score: number,
  opts: MoltrustGuardOptions
): { status: number; body: Record<string, unknown> } | null {
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  if (score < minScore) {
    return {
      status: 403,
      body: {
        error: "moltrust_score_too_low",
        message: `Agent score ${score} is below the required minimum of ${minScore}`,
        wallet,
        score,
        minScore,
      },
    };
  }
  return null;
}

/** Check score and return rejection reason or null if OK. */
export async function checkAgent(
  paymentHeader: string | null | undefined,
  opts: MoltrustGuardOptions
): Promise<{ status: number; body: Record<string, unknown>; failOpen?: boolean } | null> {
  const wallet = extractWallet(paymentHeader);
  if (!wallet) return null; // no wallet -> pass through (not an x402 request)

  const failBehavior = opts.failBehavior ?? "closed";
  const ttlMs = (opts.cacheTtlSeconds ?? 60) * 1000;
  const graceMs = (opts.cacheStaleGraceSeconds ?? 300) * 1000;

  const fresh = scoreCache.getFresh(wallet, ttlMs);
  if (fresh !== undefined) {
    return applyThreshold(wallet, fresh, opts);
  }

  const data = await fetchScore(wallet, opts);

  if (!data) {
    const stale = scoreCache.getStale(wallet, graceMs);
    if (stale !== undefined) {
      // A recent score is a better answer than either extreme while the
      // registry is briefly unreachable.
      return applyThreshold(wallet, stale, opts);
    }
    if (failBehavior === "closed") {
      return {
        status: 403,
        body: {
          error: "trust_api_unavailable",
          message: "MolTrust API is unreachable. Request denied (failBehavior: closed).",
          wallet,
        },
      };
    }
    // fail-open: pass through with marker
    return null;
  }

  scoreCache.put(wallet, data.score);

  return applyThreshold(wallet, data.score, opts);
}
