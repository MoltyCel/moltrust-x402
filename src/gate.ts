/**
 * The offline gate: price or admit a caller by what it can prove, without a
 * network call in the request path.
 *
 * `moltrustGuard` in ./core takes a wallet out of the payment header and asks
 * our API about it. That puts a call to us inside your request, and it
 * verifies nothing — the answer is JSON over TLS, so whoever can answer that
 * request sets the score.
 *
 * This is the other shape. The caller brings a MolTrust-signed attestation and
 * a signature made with its own key; both are checked against a key set you
 * already hold. We are not contacted, and nothing we could say would change
 * the outcome.
 *
 * Three implementations share one set of vectors — this one, the Python gate
 * in `moltrust-enforce`, and the copy vendored into MoltGuard. Duplicated
 * security logic drifts invisibly because each copy passes its own tests, so
 * `gate.vectors.json` is generated from a pinned clock and constant key seeds
 * and every copy replays it.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';

export const BINDING_VERSION = 'moltrust-gate/v1';
export const DEFAULT_MAX_AGE_SECONDS = 300;

export const HEADER_ATTESTATION = 'x-moltrust-attestation';
export const HEADER_TIMESTAMP = 'x-moltrust-timestamp';
export const HEADER_PROOF = 'x-moltrust-proof';

export interface Jwk {
  kty: string;
  crv: string;
  kid: string;
  x: string;
  use?: string;
  alg?: string;
}

export interface Jwks { keys: Jwk[] }

export interface GateAttestation {
  did: string;
  publicKey: string;
  trustScore: number | null;
  withheld: boolean;
  credentialTypes: string[];
  computedAt: string;
  validUntil: string;
  policyVersion: string;
  version: number;
}

export type DenialReason =
  | 'attestation_missing' | 'proof_missing' | 'attestation_invalid'
  | 'proof_invalid' | 'proof_replayed' | 'score_withheld'
  | 'score_missing' | 'score_below_minimum' | 'credential_missing';

export interface Decision {
  allowed: boolean;
  reason: DenialReason | 'ok';
  detail: string;
  did?: string;
  trustScore?: number | null;
  credentialTypes?: string[];
}

export interface GateOptions {
  minScore?: number | null;
  credentialType?: string | null;
  requiredCredentials?: string[];
  jwks: Jwks | string;
  maxAgeSeconds?: number;
  allowWithheld?: boolean;
  seen?: (proof: string) => boolean;
}

type HeaderBag = Record<string, string | string[] | undefined>
  | { get(name: string): string | undefined | null };

// --------------------------------------------------------------------------

function b64urlDecode(value: string): Buffer {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('empty base64url value');
  }
  return Buffer.from(value, 'base64url');
}

function b64urlEncode(buf: Buffer): string {
  return Buffer.from(buf).toString('base64url');
}

/**
 * Read a JWKS from a path, or accept one already in memory. Deliberately not a
 * fetch: refreshing the key set is an operational step with its own schedule,
 * and an HTTP call here would undo the property this module is for.
 *
 * Published at https://api.moltrust.ch/.well-known/jwks.json
 */
export function loadJwks(pathOrObject: Jwks | string): Jwks {
  const jwks: Jwks = typeof pathOrObject === 'string'
    ? JSON.parse(fs.readFileSync(pathOrObject, 'utf8'))
    : pathOrObject;
  if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error('JWKS has no keys[]');
  }
  return jwks;
}

function keyForKid(jwks: Jwks, kid: string): crypto.KeyObject {
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (!jwk) {
    throw new Error(
      `no key for kid ${JSON.stringify(kid)} in the JWKS — refresh it, or the `
      + 'token was not issued by this registry',
    );
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new Error(`unsupported key: kty=${jwk.kty} crv=${jwk.crv}`);
  }
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    format: 'jwk',
  });
}

function keyFromHex(hex: string): crypto.KeyObject {
  const raw = Buffer.from(hex, 'hex');
  if (raw.length !== 32) throw new Error(`public_key must be 32 bytes, got ${raw.length}`);
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: b64urlEncode(raw) },
    format: 'jwk',
  });
}

/** Verify a compact JWS gate attestation. Throws with the reason. */
export function verifyAttestation(token: string, jwks: Jwks, now?: number): GateAttestation {
  if (typeof token !== 'string') throw new Error('attestation is not a string');
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`not a compact JWS: ${parts.length} parts, expected 3`);
  }
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(b64urlDecode(headerB64).toString('utf8'));
  if (header.alg !== 'EdDSA') throw new Error(`alg=${header.alg}, expected EdDSA`);
  if (!header.kid) throw new Error('header carries no kid');

  const key = keyForKid(jwks, header.kid);
  const ok = crypto.verify(
    null, Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), key, b64urlDecode(sigB64),
  );
  if (!ok) throw new Error('signature does not cover this payload');

  const payload = JSON.parse(b64urlDecode(payloadB64).toString('utf8'));
  if (payload === null || typeof payload !== 'object') {
    throw new Error('payload is not an object');
  }
  if (payload.v !== 2) {
    throw new Error(
      `payload version ${JSON.stringify(payload.v)} is not a gate attestation — `
      + 'the v1 trust-score payload carries no public key and cannot gate anything',
    );
  }
  for (const required of ['did', 'public_key', 'valid_until']) {
    if (!payload[required]) throw new Error(`payload has no ${required}`);
  }

  const validUntil = Date.parse(payload.valid_until);
  if (Number.isNaN(validUntil)) {
    throw new Error(`not an RFC 3339 timestamp: ${payload.valid_until}`);
  }
  const current = now === undefined ? Date.now() : now;
  if (current > validUntil) {
    throw new Error(`expired at ${payload.valid_until}; ask the agent for a fresh one`);
  }

  return {
    did: payload.did,
    publicKey: payload.public_key,
    trustScore: payload.trust_score === undefined ? null : payload.trust_score,
    withheld: Boolean(payload.withheld),
    credentialTypes: payload.credential_types || [],
    computedAt: payload.computed_at || '',
    validUntil: payload.valid_until,
    policyVersion: payload.policy_version || '',
    version: payload.v,
  };
}

/**
 * What the calling agent signs. Method, path, DID and moment, newline
 * separated. Each element stops a specific reuse: a proof made for a free
 * route replayed against a paid one, a proof lifted from one agent and
 * presented by another, a proof kept and used tomorrow.
 */
export function bindingString(
  method: string, path: string, did: string, timestamp: string | number,
): Buffer {
  return Buffer.from(
    [BINDING_VERSION, String(method).toUpperCase(), path, did, String(timestamp)].join('\n'),
    'utf8',
  );
}

function verifyProof(
  att: GateAttestation, method: string, path: string, timestamp: string,
  proofB64: string, maxAgeSeconds: number, now?: number,
): string | null {
  const ts = Number(String(timestamp).trim());
  if (!Number.isFinite(ts)) return `timestamp ${JSON.stringify(timestamp)} is not a number`;
  const current = (now === undefined ? Date.now() : now) / 1000;
  const age = current - ts;
  if (age > maxAgeSeconds) return `proof is ${Math.round(age)}s old, limit ${maxAgeSeconds}s`;
  if (age < -maxAgeSeconds) {
    return `proof is ${Math.round(-age)}s in the future, limit ${maxAgeSeconds}s`;
  }

  let key: crypto.KeyObject;
  try {
    key = keyFromHex(att.publicKey);
  } catch (err) {
    return `public_key in the attestation is unusable: ${(err as Error).message}`;
  }
  let signature: Buffer;
  try {
    signature = b64urlDecode(proofB64);
  } catch (err) {
    return `proof is not base64url: ${(err as Error).message}`;
  }
  const ok = crypto.verify(null, bindingString(method, path, att.did, timestamp), key, signature);
  return ok ? null : 'proof does not verify under the attested public key';
}

function header(headers: HeaderBag, name: string): string {
  if (!headers) return '';
  const bag = headers as { get?: (n: string) => string | undefined | null };
  if (typeof bag.get === 'function') return bag.get(name) || '';
  const record = headers as Record<string, string | string[] | undefined>;
  const direct = record[name];
  if (direct) return String(direct);
  for (const [k, v] of Object.entries(record)) {
    if (k.toLowerCase() === name && v) return String(v);
  }
  return '';
}

function deny(reason: DenialReason, detail: string, extra?: Partial<Decision>): Decision {
  return { allowed: false, reason, detail, ...(extra || {}) };
}

/**
 * Build a gate. Returns a decision function; everything that is not an
 * explicit allow is a denial, including a malformed header and an unknown key
 * id, and every denial names a reason the caller can act on.
 */
export function gateFor(options: GateOptions): (
  method: string, path: string, headers: HeaderBag, now?: number
) => Decision {
  const {
    minScore = null,
    credentialType = null,
    requiredCredentials = [],
    jwks: rawJwks,
    maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS,
    allowWithheld = false,
    seen,
  } = options;

  const jwks = loadJwks(rawJwks);
  const wanted = Array.from(new Set(
    requiredCredentials.concat(credentialType ? [credentialType] : []),
  )).sort();

  return function decide(method, path, headers, now): Decision {
    const token = header(headers, HEADER_ATTESTATION);
    const proof = header(headers, HEADER_PROOF);
    const timestamp = header(headers, HEADER_TIMESTAMP);

    if (!token) {
      return deny('attestation_missing',
        `send the gate_attestation from GET /skill/trust-score/<did> in ${HEADER_ATTESTATION}. `
        + 'No DID yet: https://moltrust.ch/developers.html?from=gate');
    }
    if (!proof || !timestamp) {
      return deny('proof_missing', `${HEADER_PROOF} and ${HEADER_TIMESTAMP} are both required`);
    }

    let att: GateAttestation;
    try {
      att = verifyAttestation(token, jwks, now);
    } catch (err) {
      return deny('attestation_invalid', (err as Error).message);
    }

    const problem = verifyProof(att, method, path, timestamp, proof, maxAgeSeconds, now);
    if (problem) return deny('proof_invalid', problem, { did: att.did });

    if (seen && !seen(proof)) {
      return deny('proof_replayed', 'this proof has been presented before', { did: att.did });
    }

    // A score we have not computed is not a low score, and it is not a pass.
    if (att.withheld && !allowWithheld) {
      return deny('score_withheld',
        'no score has been computed for this agent; that is not a low score, '
        + 'and this gate does not read it as one',
        { did: att.did, credentialTypes: att.credentialTypes });
    }

    if (minScore !== null && minScore !== undefined) {
      if (att.trustScore === null) {
        return deny('score_missing', 'the attestation carries no score to compare',
          { did: att.did, credentialTypes: att.credentialTypes });
      }
      if (att.trustScore < minScore) {
        return deny('score_below_minimum', `score ${att.trustScore} is below ${minScore}`,
          { did: att.did, trustScore: att.trustScore, credentialTypes: att.credentialTypes });
      }
    }

    const missing = wanted.filter((c) => !att.credentialTypes.includes(c));
    if (missing.length) {
      return deny('credential_missing',
        `holds ${JSON.stringify(att.credentialTypes)}, needs ${JSON.stringify(missing)}`,
        { did: att.did, trustScore: att.trustScore, credentialTypes: att.credentialTypes });
    }

    return {
      allowed: true,
      reason: 'ok',
      detail: '',
      did: att.did,
      trustScore: att.trustScore,
      credentialTypes: att.credentialTypes,
    };
  };
}

// --------------------------------------------------------------------------
// Framework adapters
// --------------------------------------------------------------------------

/**
 * Express middleware. On a denial it answers 403 with the reason named, so a
 * caller can fix its own request without asking you what happened.
 */
export function requireMolTrust(options: GateOptions & {
  onDeny?: (req: any, res: any, decision: Decision) => void;
}) {
  const decide = gateFor(options);
  const onDeny = options.onDeny;
  return function moltrustGate(req: any, res: any, next: (err?: any) => void) {
    const decision = decide(req.method, req.path ?? req.url, req.headers);
    if (decision.allowed) {
      req.moltrust = decision;
      return next();
    }
    if (onDeny) return onDeny(req, res, decision);
    return res.status(403).json({
      error: decision.reason,
      detail: decision.detail,
      did: decision.did ?? null,
      docs: 'https://moltrust.ch/developers.html?from=gate',
    });
  };
}

/** The same gate for Hono. */
export function requireMolTrustHono(options: GateOptions) {
  const decide = gateFor(options);
  return async function moltrustGate(c: any, next: () => Promise<void>) {
    const decision = decide(c.req.method, new URL(c.req.url).pathname, c.req.header());
    if (decision.allowed) {
      c.set('moltrust', decision);
      return next();
    }
    return c.json({
      error: decision.reason,
      detail: decision.detail,
      did: decision.did ?? null,
      docs: 'https://moltrust.ch/developers.html?from=gate',
    }, 403);
  };
}
