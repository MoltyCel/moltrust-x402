import { checkAgent, fetchScore, extractPayment, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore, MoltGuardResult, X402Payment } from "./core";

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

    // Attach moltrust context if a payer was found
    const payment = extractPayment(paymentHeader);
    if (payment) {
      const data = await fetchScore(payment.wallet, opts);
      c.set("moltrust", {
        wallet: payment.wallet,
        score: data?.score ?? null,
        protocol: "x402",
        network: payment.network,
        failOpen: !data,
      });
    }

    await next();
  };
}
