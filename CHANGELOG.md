# Changelog

## Unreleased

### Fixed — non-EVM payers bypassed the gate

`extractWallet` validated the payer address against a hard-coded
`0x[0-9a-fA-F]{40}` regex, so any address that was not an EVM address came back
as `null`. `checkAgent` reads that `null` as "not an x402 request" and passes the
request through, which means a Casper payment was never scored at all — the
threshold was not applied, and `failBehavior: "closed"` did not deny during a
registry outage. The gate silently opened for every non-EVM payer.

Casper payer addresses are now recognized: ed25519 public keys (`01` + 64 hex),
secp256k1 public keys (`02` + 66 hex) and account hashes
(`account-hash-` + 64 hex). Public keys are normalized to lower case so one
payer is one cache key and one lookup URL; EVM addresses are still returned
verbatim, so checksummed casing is unaffected. A bare 64-hex string is not
accepted, being too ambiguous to attribute to a chain.

### Added

- `extractPayment(header)` returns `{ wallet, network }`, where `network` is the
  CAIP-2 id declared in the payload (`network` or `payload.network`) or `null`.
  Casper networks are `casper:casper` and `casper:casper-test`. `extractWallet`
  delegates to it and its signature is unchanged.
- The declared network is exposed on the Hono/Express `moltrust` context
  (`MoltGuardResult.network`) and included in the `403` body when present.
- The wallet is URL-encoded in the score lookup path. This is a no-op for every
  accepted address shape and is there so a new one cannot alter the URL.

Nothing that worked before behaves differently: EVM payers take the same path,
produce the same lookups and the same responses.

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
