import { checkAgent, fetchScore, extractWallet, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore, MoltGuardResult } from "./core";

/**
 * Hono middleware that checks the paying agent's MoltGuard score.
 *
 * ```ts
 * app.use(moltrustGuard({ minScore: 50, failBehavior: 'open' }))
 * ```
 */
export function moltrustGuard(opts: MoltrustGuardOptions = {}) {
  return async (c: any, next: () => Promise<void>) => {
    const paymentHeader =
      c.req.header("payment-signature") ??
      c.req.header("x-payment");
    const rejection = await checkAgent(paymentHeader, opts);
    if (rejection) {
      return c.json(rejection.body, rejection.status);
    }

    // Attach moltrust context if wallet found
    const wallet = extractWallet(paymentHeader);
    if (wallet) {
      const data = await fetchScore(wallet, opts);
      c.set("moltrust", {
        wallet,
        score: data?.score ?? null,
        protocol: "x402",
        failOpen: !data,
      });
    }

    await next();
  };
}
