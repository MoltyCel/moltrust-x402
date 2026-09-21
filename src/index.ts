export { moltrustGuard as default } from "./hono";
export { moltrustGuard } from "./hono";
export { moltrustGuard as moltrustGuardExpress } from "./express";
export type { MoltrustGuardOptions, MoltGuardScore } from "./core";

// The offline gate. Prefer this over moltrustGuard above: it verifies a
// signature instead of trusting an HTTP answer, and it makes no network call
// while your request is in flight.
export { requireMolTrust, requireMolTrustHono, gateFor, verifyAttestation,
         bindingString, loadJwks, BINDING_VERSION,
         HEADER_ATTESTATION, HEADER_TIMESTAMP, HEADER_PROOF } from "./gate";
export type { GateOptions, Decision, DenialReason, GateAttestation,
              Jwk, Jwks } from "./gate";
