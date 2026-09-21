# @moltrust/x402

## The offline gate — `requireMolTrust` (2.0.0)

```js
const { requireMolTrust, loadJwks } = require('@moltrust/x402');
const jwks = loadJwks('/etc/moltrust/jwks.json');

app.post('/audit', requireMolTrust({ minScore: 50, jwks }), handler);
```

The caller sends three headers — a MolTrust-signed attestation, a timestamp,
and a signature made with its own key — and both are checked against a key set
you already hold. **Nothing on our side is contacted while your request is in
flight.** The only thing that has to reach us is a periodic refresh of that key
set, on your schedule.

### Why this exists next to `moltrustGuard`

`moltrustGuard` takes a wallet out of the payment header and asks our API about
it. That puts a call to us inside your request, and it verifies nothing: the
answer is JSON over TLS, so whoever can answer that request decides the score.
It is still exported and still works. This is the shape to prefer.

### A discount rather than a gate

Two prices on one route. Nobody is turned away, the price moves:

```js
const verified = gateFor({ minScore: 50, jwks });

app.get('/report', (req, res, next) => {
  const d = verified(req.method, req.path, req.headers);
  req.price = d.allowed ? '0.04' : '0.05';   // 20 % off, what we run ourselves
  next();
}, paywall(), handler);
```

### Deny by default

Every path that is not an explicit allow is a denial — a malformed header, an
unknown key id, an expired attestation — and each one names a `reason`:
`attestation_missing`, `attestation_invalid`, `proof_invalid`, `proof_replayed`,
`score_withheld`, `score_missing`, `score_below_minimum`, `credential_missing`.

**A withheld score is a denial.** A score we have not computed is not a low
score and it is not a pass. `allowWithheld: true` lets those callers through —
reasonable for a discount tier, a bad idea for a spend authorisation — and it
does not bypass `minScore`, because a withheld score is `null`.

### Replay

The proof is fresh within `maxAgeSeconds` (default 300). Inside that window the
same proof can be presented twice unless you pass `seen`. Without it the gate is
replay-resistant, not replay-proof.

### Keeping the key set current

```bash
curl -fsS https://api.moltrust.ch/.well-known/jwks.json > /etc/moltrust/jwks.json.new \
  && mv /etc/moltrust/jwks.json.new /etc/moltrust/jwks.json
```

A rotated key surfaces as `attestation_invalid` with `no key for kid …` — the
one denial that means refresh the file rather than blame the caller.


MolTrust trust verification middleware for [x402](https://www.x402.org/) payments. Checks the paying agent's [MoltGuard](https://moltrust.ch/moltguard.html) reputation score before allowing payment flow.

## Install

```bash
npm install @moltrust/x402
```

## Hono

```ts
import { Hono } from "hono";
import { moltrustGuard } from "@moltrust/x402";

const app = new Hono();
app.use(moltrustGuard({ minScore: 50 }));
```

## Express

```ts
import express from "express";
import { moltrustGuard } from "@moltrust/x402/express";

const app = express();
app.use(moltrustGuard({ minScore: 50 }));
```

## How it works

1. Extracts wallet address from the `X-PAYMENT` header
2. Calls MoltGuard's free agent scoring endpoint
3. Returns `403` if score is below `minScore`
4. Passes through if score is OK
5. **Fails open** if MoltGuard is unreachable (never blocks payments on downtime)

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minScore` | `number` | `50` | Minimum score (0–100) to allow |
| `apiUrl` | `string` | `https://api.moltrust.ch/guard` | MoltGuard API base URL |
| `timeout` | `number` | `3000` | Timeout in ms |

## License

MIT — [moltrust.ch](https://moltrust.ch)
