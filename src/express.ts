import { checkAgent, fetchScore, extractPayment, type MoltrustGuardOptions } from "./core";

export type { MoltrustGuardOptions, MoltGuardScore, MoltGuardResult, X402Payment } from "./core";

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

    // Attach moltrust context if a payer was found
    const payment = extractPayment(paymentHeader);
    if (payment) {
      const data = await fetchScore(payment.wallet, opts);
      req.moltrust = {
        wallet: payment.wallet,
        score: data?.score ?? null,
        protocol: "x402",
        network: payment.network,
        failOpen: !data,
      };
    }

    next();
  };
}
