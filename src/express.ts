import { checkAgent, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore } from "./core";

/**
 * Express middleware that checks the paying agent's MoltGuard score
 * before allowing x402 payment flow.
 *
 * ```ts
 * app.use(moltrustGuard({ minScore: 50 }))
 * ```
 */
export function moltrustGuard(opts: MoltrustGuardOptions = {}) {
  return async (req: any, res: any, next: (err?: any) => void) => {
    const xPayment = req.headers["x-payment"] as string | undefined;
    const rejection = await checkAgent(xPayment, opts);
    if (rejection) {
      return res.status(rejection.status).json(rejection.body);
    }
    next();
  };
}
