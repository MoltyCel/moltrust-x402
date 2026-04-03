import { checkAgent, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore } from "./core";

/**
 * Hono middleware that checks the paying agent's MoltGuard score
 * before allowing x402 payment flow.
 *
 * Reads PAYMENT-SIGNATURE (v2) first, then X-PAYMENT (v1 backward compat).
 *
 * ```ts
 * app.use(moltrustGuard({ minScore: 50 }))
 * ```
 */
export function moltrustGuard(opts: MoltrustGuardOptions = {}) {
  return async (c: any, next: () => Promise<void>) => {
    // v2 first, then v1 backward compat
    const paymentHeader =
      c.req.header("payment-signature") ??
      c.req.header("x-payment");
    const rejection = await checkAgent(paymentHeader, opts);
    if (rejection) {
      return c.json(rejection.body, rejection.status);
    }
    await next();
  };
}
