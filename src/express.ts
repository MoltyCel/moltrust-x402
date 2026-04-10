import { checkAgent, fetchScore, extractWallet, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore, MoltGuardResult } from "./core";

/**
 * Express middleware that checks the paying agent's MoltGuard score.
 *
 * ```ts
 * app.use(moltrustGuard({ minScore: 50, failBehavior: 'open' }))
 * ```
 */
export function moltrustGuard(opts: MoltrustGuardOptions = {}) {
  return async (req: any, res: any, next: (err?: any) => void) => {
    const paymentHeader =
      (req.headers["payment-signature"] as string | undefined) ??
      (req.headers["x-payment"] as string | undefined);
    const rejection = await checkAgent(paymentHeader, opts);
    if (rejection) {
      return res.status(rejection.status).json(rejection.body);
    }

    // Attach moltrust context if wallet found
    const wallet = extractWallet(paymentHeader);
    if (wallet) {
      const data = await fetchScore(wallet, opts);
      req.moltrust = {
        wallet,
        score: data?.score ?? null,
        protocol: "x402",
        failOpen: !data,
      };
    }

    next();
  };
}
