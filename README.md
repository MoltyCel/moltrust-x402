# @moltrust/x402

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

## Payer address formats

The payer is read from `payload.fromAddress`, `fromAddress`,
`payload.authorization.from` or `from` in the decoded payment header, and is
recognized in these forms:

| Chain | Format | Example |
|-------|--------|---------|
| EVM | `0x` + 40 hex | `0x1111…1111` |
| Casper | ed25519 public key: `01` + 64 hex | `01aaaa…aaaa` |
| Casper | secp256k1 public key: `02` + 66 hex | `02bbbb…bbbb` |
| Casper | account hash: `account-hash-` + 64 hex | `account-hash-cccc…cccc` |

Casper public keys are lower-cased before lookup so one payer is one cache key;
EVM addresses are passed through unchanged so checksum casing survives. A bare
64-hex string is not accepted — it is an account hash without its prefix, but
also the shape of a raw hash on other chains, so it is too ambiguous to treat as
a payer. Anything unrecognized yields no wallet and the request is not gated.

If the payload carries a CAIP-2 `network`, it is read from `network` or
`payload.network` and included in the middleware context and in the `403` body.
Casper networks are `casper:casper` (mainnet) and `casper:casper-test`
(testnet). Casper x402 payments settle in wCSPR (CEP-18) through the Casper
facilitator at [x402-facilitator.cspr.cloud](https://x402-facilitator.cspr.cloud)
([docs](https://docs.cspr.cloud)).

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minScore` | `number` | `50` | Minimum score (0–100) to allow |
| `apiUrl` | `string` | `https://api.moltrust.ch/guard` | MoltGuard API base URL |
| `timeout` | `number` | `3000` | Timeout in ms |

## License

MIT — [moltrust.ch](https://moltrust.ch)
