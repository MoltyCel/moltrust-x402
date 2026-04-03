import { checkAgent, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore } from "./core";

/**
 * Express middleware that checks the paying agent's MoltGuard score
 * before allowing x402 payment flow.
 *
 * Reads PAYMENT-SIGNATURE (v2) first, then X-PAYMENT (v1 backward compat).
 *
 * ```ts
 * app.use(moltrustGuard({ minScore: 50 }))
 * ```
 */
export function moltrustGuard(opts: MoltrustGuardOptions = {}) {
  return async (req: any, res: any, next: (err?: any) => void) => {
    // v2 first, then v1 backward compat
    const paymentHeader =
      (req.headers["payment-signature"] as string | undefined) ??
      (req.headers["x-payment"] as string | undefined);
    const rejection = await checkAgent(paymentHeader, opts);
    if (rejection) {
      return res.status(rejection.status).json(rejection.body);
    }
    next();
  };
}
