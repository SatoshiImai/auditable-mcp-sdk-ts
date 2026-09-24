# Changelog

Changes to the Auditable MCP TypeScript SDK. The SDK package version is independent of the
`spec_version` it implements (currently `auditable-mcp/0.3`); this file tracks the package.

## 0.3.0

Breaking, tracking spec `auditable-mcp/0.3`. The Python SDK's 0.3.0 is the same change; the two ports
stay symmetric by design.

### Breaking changes

- **Emission moves to `auditable-mcp/0.3`**, so every golden digest changes; the verifier stays
  read-lenient and still accepts records sealed under any published version.
- **`AuditCapability` gains a REQUIRED `witness`** of `none` or `host` (§5.2, §6.1).
- **`negotiate(host, tool)` replaces the single-axis fit.** `capabilitySatisfies` splits into
  `levelSatisfies` and `witnessSatisfies` because the axes run in opposite directions, `host` may be
  `undefined` for a peer that declared nothing, and the result carries a `NegotiationOutcome` rather
  than a boolean `satisfied`: an absent negotiation is not a failed one, and §6.2 governs it
  differently.
- **`VerifyReport` gains `unchecked` and `complete`** (§11.4), so a caller that only reads `ok`
  cannot mistake an unchecked signature for a verified one.

### Added

- **The witness axis.** `AuditHost` takes a `witnessSigner` (`Ed25519WitnessSigner`) and signs every
  sealed record, attempts and outcomes alike; an outcome's signature is written into the ledger,
  since `audit/outcome` has no response channel. `AmcpSession` takes a `witnessVerifier`
  (`WitnessRegistryVerifier`) and enforces §7.2's precedence. `SealedRecord` carries
  `host_signature` / `host_key_id`, absent when unwitnessed.
- **Atomic sealing (§7.1).** `AuditHost` holds one lock per partition across validation, sealing and
  commit. Without it, concurrent attempts against a durable or witnessing host read the same chain
  tail, take the same `seq` and `previous_hash`, and are all answered `accept` - the tool acts on
  records the ledger cannot hold. The in-memory, unwitnessed host was the only configuration without
  the window, which is why the suite never saw it.
- **`auditable-mcp-sdk/reasons`** is an entry point. The Tier-1 vocabulary was importable from no
  entry point at all, though this file already named `HOST_UNWITNESSED` as a public addition; the
  Python port has always had it as `auditable_mcp.reasons`.
- **`transportFor`** picks what §6.2 permits for a session that was not negotiated, and refuses to
  return a transport for the third, non-conformant posture.
- **The MCP wire binding** (`auditable-mcp-sdk/mcp`). `McpAuditTransport` (tool) and
  `McpAuditReceiver` (host) carry `audit/attempt` and `audit/outcome` on a real MCP connection by
  wrapping the transport the session is given; neither official SDK dispatches a method outside its
  own request union, and neither has to. The seams also declare this extension on `initialize` and
  read the peer's declaration back. Three §6 obligations are enforced only here: an attempt is never
  batched, the wait for a decision is bounded and fails closed, and an unnegotiated session carries
  no audit message at all. The entry point declares the MCP transport surface structurally, so it
  adds no dependency.
- `HOST_UNWITNESSED` / `HOST_SIGNATURE_INVALID`; `witnessPayload`; `verifyDetachedSignature`.

### Fixed

- `verifyDetachedSignature` called the Ed25519 engine as `verify(signature, payload, key)` where the
  interface is `verify(message, signature, key)`. Caught by the first test written against it.

## 0.2.1

Non-breaking. Existing code is unaffected; the new check is off unless a deployment opts in.

### Added

- `RecordAdapter.principalOf` (optional) and an `expectedPrincipal` argument on `verifyChain` /
  `verifyLedger`. When an expected principal is supplied, each record's extracted governed identity is
  compared against it (strict equality); an absent or non-matching identity is reported as a
  `principal-mismatch` anomaly. This lets a verifier detect a cross-partition transplant when a-MCP
  records are sealed inside an outer envelope (for example SEP-3004) that binds the principal. Identity
  binding is the envelope's concern; the SDK supplies only the read seam (`principalOf`) and the
  comparison.
- `principal-mismatch`: a new SDK-defined anomaly kind (in neither a-MCP §7.6 nor SEP-3004), emitted on
  `VerifyIssue.kind`. As with every kind, the public contract is the fixed string value — compare
  `issue.kind === 'principal-mismatch'`.

### Changed

- `DEFAULT_ADAPTER` is now frozen (`Object.freeze`), so the shared process-wide default cannot be
  mutated. Spread it to override only what you need. This affects only code that mutated the exported
  default in place, which was never a supported use.

Defaults are inert: `principalOf` is absent (treated as `undefined`) and `expectedPrincipal` defaults to
`undefined`, so the comparison runs only when a deployment provides both an adapter that reads its
envelope's identity and the partition's expected principal.

### Fixed

- `verifyChain` no longer reports a record whose `RecordAdapter.idOf` returns `undefined`/`null` as an
  `orphaned-outcome`. Such a record names no call, so it is exempt from attempt/outcome correlation: an
  envelope that seals records which are not tool calls (a prompt, a model's reasoning, a turn boundary)
  previously had every one flagged as a terminal outcome with a missing attempt, so an intact chain
  verified as broken. The exemption is per record and seeds nothing; a real tool outcome whose
  correlation key is present is still reported. Correlation of records that do name a call is unchanged.
- Installing from a git ref now builds the package. A `prepare` script runs the build on install, so
  `dist/` (referenced by `exports`, and not committed to the repo) is generated for the consumer;
  without it a git-ref install resolved `exports` to a missing `dist/` and failed to import.

See [docs/expected-principal.md](docs/expected-principal.md) for the background: what a-MCP, SEP-3004, and this check each cover.

## 0.2.0

- Verification is read-lenient on `spec_version`: a verifier accepts records sealed under any published
  version (`auditable-mcp/0.1`, `/0.1.1`, `/0.2`), while emission and ingest stay pinned to the current
  version. Sealed bytes are immutable evidence.
- `RecordAdapter` (`idOf` / `isAttempt` / `eventOf`): the verifier can correlate and schema-check
  a-MCP records sealed inside an outer envelope, without the SDK importing any specific envelope shape.
