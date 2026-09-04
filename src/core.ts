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
  /** CAIP-2 network the payment declared, when the payload carried one. */
  network?: string | null;
  failOpen?: boolean;
}

/** Payer identity and declared network, as read from an x402 payment header. */
export interface X402Payment {
  wallet: string;
  network: string | null;
}

const DEFAULT_API = "https://api.moltrust.ch/guard";
const DEFAULT_MIN_SCORE = 50;
const DEFAULT_TIMEOUT = 3000;

/** EVM (eip155) payer address. */
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** Casper ed25519 public key: 01 tag + 32 bytes. */
const CASPER_ED25519 = /^01[0-9a-fA-F]{64}$/;

/** Casper secp256k1 public key: 02 tag + 33 bytes. */
const CASPER_SECP256K1 = /^02[0-9a-fA-F]{66}$/;

/** Casper account hash, prefix included. */
const CASPER_ACCOUNT_HASH = /^account-hash-([0-9a-fA-F]{64})$/;

/**
 * Normalize a payer address, or return null if it is not one we recognize.
 *
 * EVM addresses are returned verbatim so checksummed casing survives. Casper
 * public keys are lower-cased so the same payer always hits the same cache key
 * and the same score URL; an account hash keeps its `account-hash-` prefix with
 * a lower-cased tail.
 *
 * A bare 64-hex string is deliberately NOT accepted: it is an account hash
 * without its prefix, but it is also the shape of a raw hash on several other
 * chains, so treating it as a Casper payer would be a guess.
 */
function normalizeAddress(addr: unknown): string | null {
  if (typeof addr !== "string") return null;
  const value = addr.trim();
  if (EVM_ADDRESS.test(value)) return value;
  if (CASPER_ED25519.test(value) || CASPER_SECP256K1.test(value)) return value.toLowerCase();
  const accountHash = CASPER_ACCOUNT_HASH.exec(value);
  if (accountHash) return `account-hash-${accountHash[1].toLowerCase()}`;
  return null;
}

/**
 * Extract the payer address and declared network from an x402 payment header.
 *
 * Supports both:
 * - v2: PAYMENT-SIGNATURE header (base64 JSON with payload.fromAddress)
 * - v1: X-PAYMENT header (same format, backward compat)
 *
 * Recognized payer addresses are EVM `0x…` addresses and Casper payers
 * (ed25519 / secp256k1 public keys, or an `account-hash-…`). The network is the
 * CAIP-2 id the payload declared, if any — `eip155:8453`, `casper:casper`,
 * `casper:casper-test` — and is null when the payload does not carry one.
 */
export function extractPayment(paymentHeader: string | null | undefined): X402Payment | null {
  if (!paymentHeader) return null;
  try {
    const raw = paymentHeader.startsWith("x402 ") ? paymentHeader.slice(5) : paymentHeader;
    const decoded = JSON.parse(Buffer.from(raw, "base64").toString());
    const wallet = normalizeAddress(
      decoded?.payload?.fromAddress ??
        decoded?.fromAddress ??
        decoded?.payload?.authorization?.from ??
        decoded?.from
    );
    if (!wallet) return null;
    const declared = decoded?.network ?? decoded?.payload?.network;
    return { wallet, network: typeof declared === "string" && declared ? declared : null };
  } catch {
    return null;
  }
}

/**
 * Extract wallet address from x402 payment header.
 *
 * Supports both:
 * - v2: PAYMENT-SIGNATURE header (base64 JSON with payload.fromAddress)
 * - v1: X-PAYMENT header (same format, backward compat)
 */
export function extractWallet(paymentHeader: string | null | undefined): string | null {
  return extractPayment(paymentHeader)?.wallet ?? null;
}

/** Fetch agent score from MoltGuard. Returns null on any failure. */
export async function fetchScore(
  wallet: string,
  opts: MoltrustGuardOptions
): Promise<MoltGuardScore | null> {
  const base = (opts.apiUrl ?? DEFAULT_API).replace(/\/+$/, "");
  // Encoded because payer ids are no longer all `0x` + hex. encodeURIComponent
  // leaves an EVM address and an `account-hash-…` untouched, so this is a
  // no-op for every address shape the middleware accepts today.
  const url = `${base}/api/agent/score-free/${encodeURIComponent(wallet)}`;
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
  opts: MoltrustGuardOptions,
  network: string | null = null
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
        ...(network ? { network } : {}),
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
  const payment = extractPayment(paymentHeader);
  if (!payment) return null; // no recognized payer -> pass through (not an x402 request)
  const { wallet, network } = payment;

  const failBehavior = opts.failBehavior ?? "closed";
  const ttlMs = (opts.cacheTtlSeconds ?? 60) * 1000;
  const graceMs = (opts.cacheStaleGraceSeconds ?? 300) * 1000;

  const fresh = scoreCache.getFresh(wallet, ttlMs);
  if (fresh !== undefined) {
    return applyThreshold(wallet, fresh, opts, network);
  }

  const data = await fetchScore(wallet, opts);

  if (!data) {
    const stale = scoreCache.getStale(wallet, graceMs);
    if (stale !== undefined) {
      // A recent score is a better answer than either extreme while the
      // registry is briefly unreachable.
      return applyThreshold(wallet, stale, opts, network);
    }
    if (failBehavior === "closed") {
      return {
        status: 403,
        body: {
          error: "trust_api_unavailable",
          message: "MolTrust API is unreachable. Request denied (failBehavior: closed).",
          wallet,
          ...(network ? { network } : {}),
        },
      };
    }
    // fail-open: pass through with marker
    return null;
  }

  scoreCache.put(wallet, data.score);

  return applyThreshold(wallet, data.score, opts, network);
}
