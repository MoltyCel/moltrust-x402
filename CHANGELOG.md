# Changelog

## 2.0.0

`requireMolTrust` — an offline gate. The caller presents a MolTrust-signed
attestation and a signature made with its own key; both are verified against a
cached JWKS. No network call in the request path.

Why it matters: `moltrustGuard`, the middleware this package has shipped since
0.1.0, asks our API for a score on every request and believes the answer. That
puts a call to us inside someone else's request path, and it verifies nothing —
the response is JSON over TLS, so whoever can answer that request sets the
score. `moltrustGuard` is still exported; this is the shape to prefer.

Deny by default, with a named reason on every denial. A withheld score is a
denial: it is not a low score and it is not a pass.

Three implementations share one set of vectors — this one, `moltrust-enforce`
in Python, and the copy vendored into MoltGuard. `src/gate.vectors.json` is
generated from a pinned clock and constant key seeds, and every copy replays
all seventeen.

Adapters for Express (`requireMolTrust`) and Hono (`requireMolTrustHono`).
Node >= 18; Ed25519 comes from `node:crypto`, so no new dependency.

## 0.2.0 — 2026-08-31

### Changed — behaviour, not API (read before upgrading)

**A failed trust lookup now denies instead of allowing.**

Until 0.1.x, `failBehavior` defaulted to `"open"`, so a registry or transport
error let the call through. A gate that opens when the registry is unreachable does
not gate anything, so the default is now to deny with
`trust_api_unavailable` (HTTP 403).

Nothing in the signature changed and no call site has to be touched. What
changes is what happens during an outage: previously every agent passed, now
every agent is refused unless one of the two release valves applies.

**Two release valves.**

1. A short cache. A successful lookup is reused for `cacheTtlSeconds`
   (default 60) with no network call. If a live lookup then fails, a score up
   to `cacheStaleGraceSeconds` old (default 300) is still used and the
   decision is made on it — the reason gains a `_cached_stale` suffix so it is
   visible in the logs that the answer was not fresh. A registry blip of a few
   minutes therefore changes nothing for agents that were seen recently.

2. Per-integration opt-out:

   ```ts
   checkAgent(header, { failBehavior: "open" })
   ```

   or, without a code change, `failBehavior: "open"` in the options object passed at
   construction.

### Migration

- Upgrading and doing nothing gets you fail-closed. Decide whether that is what
  you want **before** deploying: during a MolTrust outage your agents stop
  rather than continue.
- If continuity matters more than enforcement for your integration, set
  `failBehavior: "open"` in the options and keep it in code review rather than in
  the environment.
- The cache is per process. A fleet that restarts often gets less benefit from
  it; raise `cacheStaleGraceSeconds` if that matters.
- Authoritative negatives are unchanged: unregistered agents and scores below
  the threshold blocked before and block now, and `failBehavior` does not affect
  them.

## 0.1.x

Initial releases. Lookup errors allowed the call through.
