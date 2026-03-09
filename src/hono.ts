import { checkAgent, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore } from "./core";

/**
 * Hono middleware that checks the paying agent's MoltGuard score
 * before allowing x402 payment flow.
 *
 * ```ts
 * app.use(moltrustGuard({ minScore: 50 }))
 * ```
 */
export function moltrustGuard(opts: MoltrustGuardOptions = {}) {
  return async (c: any, next: () => Promise<void>) => {
    const xPayment = c.req.header("x-payment");
    const rejection = await checkAgent(xPayment, opts);
    if (rejection) {
      return c.json(rejection.body, rejection.status);
    }
    await next();
  };
}
