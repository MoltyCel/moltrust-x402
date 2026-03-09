export interface MoltrustGuardOptions {
  /** Minimum MoltGuard score to allow (0-100). Default: 50 */
  minScore?: number;
  /** MoltGuard API base URL. Default: https://api.moltrust.ch/guard */
  apiUrl?: string;
  /** Timeout in ms for the score lookup. Default: 3000 */
  timeout?: number;
}

export interface MoltGuardScore {
  wallet: string;
  score: number;
  _meta?: Record<string, unknown>;
}

const DEFAULT_API = "https://api.moltrust.ch/guard";
const DEFAULT_MIN_SCORE = 50;
const DEFAULT_TIMEOUT = 3000;

/**
 * Extract wallet address from x402 X-PAYMENT header.
 * The header is a base64-encoded JSON with a `payload` containing `fromAddress`.
 */
export function extractWallet(xPayment: string | null | undefined): string | null {
  if (!xPayment) return null;
  try {
    const decoded = JSON.parse(Buffer.from(xPayment, "base64").toString());
    const addr: string | undefined =
      decoded?.payload?.fromAddress ??
      decoded?.fromAddress ??
      decoded?.payload?.authorization?.from;
    if (addr && /^0x[0-9a-fA-F]{40}$/.test(addr)) return addr;
    return null;
  } catch {
    return null;
  }
}

/** Fetch agent score from MoltGuard. Returns null on any failure (fail-open). */
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
  xPayment: string | null | undefined,
  opts: MoltrustGuardOptions
): Promise<{ status: number; body: Record<string, unknown> } | null> {
  const wallet = extractWallet(xPayment);
  if (!wallet) return null; // no wallet → pass through (not an x402 request)

  const data = await fetchScore(wallet, opts);
  if (!data) return null; // fail open — MoltGuard unreachable

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
