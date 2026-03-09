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

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minScore` | `number` | `50` | Minimum score (0–100) to allow |
| `apiUrl` | `string` | `https://api.moltrust.ch/guard` | MoltGuard API base URL |
| `timeout` | `number` | `3000` | Timeout in ms |

## License

MIT — [moltrust.ch](https://moltrust.ch)
