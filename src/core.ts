export interface MoltrustGuardOptions {
  /** Minimum MoltGuard score to allow (0-100). Default: 50 */
  minScore?: number;
  /** MoltGuard API base URL. Default: https://api.moltrust.ch/guard */
  apiUrl?: string;
  /** Timeout in ms for the score lookup. Default: 3000 */
  timeout?: number;
  /** Behavior when MolTrust API is unreachable. Default: 'open' */
  failBehavior?: "open" | "closed";
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

/** Check score and return rejection reason or null if OK. */
export async function checkAgent(
  paymentHeader: string | null | undefined,
  opts: MoltrustGuardOptions
): Promise<{ status: number; body: Record<string, unknown>; failOpen?: boolean } | null> {
  const wallet = extractWallet(paymentHeader);
  if (!wallet) return null; // no wallet -> pass through (not an x402 request)

  const data = await fetchScore(wallet, opts);
  const failBehavior = opts.failBehavior ?? "open";

  if (!data) {
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

  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  if (data.score < minScore) {
    return {
      status: 403,
      body: {
        error: "moltrust_score_too_low",
        message: `Agent score ${data.score} is below the required minimum of ${minScore}`,
        wallet,
        score: data.score,
        minScore,
      },
    };
  }

  return null; // score OK
}
