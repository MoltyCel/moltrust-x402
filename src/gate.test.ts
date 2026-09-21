/**
 * The vendored gate must behave exactly like the reference it was copied from.
 *
 * `moltrust-gate.ts` is a copy of `@moltrust/x402` 2.0.0, which lives in the
 * moltrust-api repository. Until that package is on npm this one cannot import
 * it, and a duplicated security check drifts — invisibly, because each copy
 * passes its own tests.
 *
 * So the reference emits `moltrust-gate.vectors.json` from constant key seeds
 * and a pinned clock, and this file replays every vector. A failure means the
 * two have diverged, whichever one is wrong.
 *
 * The unit cases below it cover the moltguard configuration specifically:
 * 20 % off at score >= 50, withheld denied.
 */

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  bindingString, gateFor, loadJwks, verifyAttestation,
  type Jwks,
} from './gate.js';
// Imported rather than read off disk. The build compiles this file into dist/
// and the suite runs there too; a readFileSync next to the compiled copy looks
// for a JSON that tsc never emitted. As an import, resolveJsonModule carries
// the vectors along with the code that replays them.
import fixture from './gate.vectors.json' with { type: 'json' };

describe('parity with @moltrust/x402', () => {
  it('replays every reference vector', () => {
    expect(fixture.vectors.length).toBeGreaterThanOrEqual(15);
    for (const v of fixture.vectors) {
      const decide = gateFor({ jwks: fixture.jwks, ...v.options });
      const got = decide(v.method, v.path, v.headers, fixture.now_ms);
      expect(`${v.name}: ${got.reason}`).toBe(`${v.name}: ${v.expected.reason}`);
      expect(got.allowed, `${v.name}: ${got.detail}`).toBe(v.expected.allowed);
    }
  });

  it('covers the cases a gate gets wrong', () => {
    const reasons = new Set(fixture.vectors.map((v: { expected: { reason: string } }) =>
      v.expected.reason));
    for (const required of ['ok', 'score_below_minimum', 'score_withheld',
      'attestation_invalid', 'proof_invalid', 'credential_missing',
      'attestation_missing']) {
      expect(reasons.has(required), `no vector produces ${required}`).toBe(true);
    }
  });
});

// --------------------------------------------------------------------------
// The MoltGuard configuration
// --------------------------------------------------------------------------

const b64 = (b: Buffer | Uint8Array) => Buffer.from(b).toString('base64url');

function keyFromSeed(byte: number) {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.alloc(32, byte),
  ]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return { priv, pub: crypto.createPublicKey(priv) };
}

const registry = keyFromSeed(0xa1);
const agent = keyFromSeed(0xb2);
const KID = 'moltguard-test';
const DID = 'did:moltrust:000000000000000f';
const agentHex = Buffer.from(
  (agent.pub.export({ format: 'jwk' }) as { x: string }).x, 'base64url',
).toString('hex');

const jwks: Jwks = {
  keys: [{
    kty: 'OKP', crv: 'Ed25519', kid: KID,
    x: (registry.pub.export({ format: 'jwk' }) as { x: string }).x,
  }],
};

const NOW = Date.UTC(2026, 9, 15, 9, 0, 0);

function attestation(over: Record<string, unknown> = {}) {
  const payload = {
    v: 2,
    did: DID,
    public_key: agentHex,
    trust_score: 75,
    withheld: false,
    credential_types: ['AgentTrustCredential'],
    computed_at: new Date(NOW).toISOString(),
    valid_until: new Date(NOW + 3600_000).toISOString(),
    policy_version: 'phase2',
    ...over,
  };
  const h = b64(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: KID })));
  const p = b64(Buffer.from(JSON.stringify(payload)));
  return `${h}.${p}.${b64(crypto.sign(null, Buffer.from(`${h}.${p}`, 'ascii'), registry.priv))}`;
}

function headers(token: string, method = 'GET', path = '/api/agent/score') {
  const ts = String(Math.floor(NOW / 1000));
  return {
    'x-moltrust-attestation': token,
    'x-moltrust-timestamp': ts,
    'x-moltrust-proof': b64(crypto.sign(null, bindingString(method, path, DID, ts), agent.priv)),
  };
}

describe('a gate configured the way MoltGuard runs it', () => {
  const discount = gateFor({ minScore: 50, allowWithheld: false, jwks });

  it('grants the discount at score 50', () => {
    const d = discount('GET', '/api/agent/score',
      headers(attestation({ trust_score: 50 })), NOW);
    expect(d.allowed).toBe(true);
  });

  it('refuses it just below 50', () => {
    const d = discount('GET', '/api/agent/score',
      headers(attestation({ trust_score: 49.99 })), NOW);
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('score_below_minimum');
  });

  it('refuses a withheld score — allowWithheld is false here on purpose', () => {
    const d = discount('GET', '/api/agent/score',
      headers(attestation({ trust_score: null, withheld: true })), NOW);
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('score_withheld');
  });

  it('refuses a proof made for a different route', () => {
    const d = discount('GET', '/api/sybil/scan',
      headers(attestation(), 'GET', '/api/agent/score'), NOW);
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('proof_invalid');
  });

  it('refuses a request with no gate headers at all', () => {
    const d = discount('GET', '/api/agent/score', {}, NOW);
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('attestation_missing');
  });

  it('opens no socket', () => {
    const net = require('node:net');
    const original = net.Socket.prototype.connect;
    net.Socket.prototype.connect = () => { throw new Error('the gate opened a socket'); };
    try {
      expect(discount('GET', '/api/agent/score', headers(attestation()), NOW).allowed).toBe(true);
    } finally {
      net.Socket.prototype.connect = original;
    }
  });
});

describe('loading', () => {
  it('refuses an empty JWKS at build time', () => {
    expect(() => gateFor({ minScore: 50, jwks: { keys: [] } })).toThrow(/no keys/);
  });

  it('accepts a JWKS object unchanged', () => {
    expect(loadJwks(jwks).keys).toHaveLength(1);
  });

  it('exposes verifyAttestation on its own', () => {
    const att = verifyAttestation(attestation(), jwks, NOW);
    expect(att.did).toBe(DID);
    expect(att.publicKey).toBe(agentHex);
    expect(att.version).toBe(2);
  });
});
