# Changelog

Changes to the Auditable MCP TypeScript SDK. The SDK package version is independent of the
`spec_version` it implements (currently `auditable-mcp/0.3`); this file tracks the package.

## 0.3.0

Breaking, tracking spec `auditable-mcp/0.3`. The Python SDK's 0.3.0 is the same change; the two ports
stay symmetric by design.

### Breaking changes

- **Emission moves to `auditable-mcp/0.3`**, so every golden digest changes. The verifier stays
  read-lenient: a record sealed under any published version still verifies, each against the schema of
  its own version.
- **An audit session is one `tools/call` (§6.3).** The event's `call_id` becomes `session_id`, a UUID
  the host issues. `AuditHost.openSession` / `closeSession` / `withSession` issue and end one, and the
  host refuses events of a session it did not issue. `AmcpSession` takes that id; `newSessionId()`
  mints one for a tool that is its own host.
- **`signer_seq` counts from zero in each session (§7.4).** The signers lose `startSequence`: nothing
  about the count outlives the call, so there is nothing to seed or store. The host keeps, per key and
  session, the set of `signer_seq` values it decided (a replay is a decided value) and the highest value
  received with a verifying signature (the gap bound).
- **A byte-identical repeat of a sealed attempt gets the original accept (§7.1).** A retry after a
  lost answer is idempotent rather than a replay. `retryable` leaves the `unavailable` response.
- **`AuditCapability` gains a REQUIRED `countersign`** of `none` or `host` (§5.2, §6.1).
- **`negotiate(host, tool)` replaces `capabilitySatisfies`.** The two axes run in opposite directions,
  so the fit splits into `levelSatisfies` and `countersignSatisfies`; `host` may be `undefined` for a
  peer that declared nothing, and the result carries a `NegotiationOutcome`: an absent negotiation is
  not a failed one, and a call that carries no audit session is `NO_SESSION`.
- **Signatures are JOSE (§12.1).** Every signature is unpadded base64url, and the algorithms are named
  `Ed25519` (RFC 9864) and `ES256`. A JWK whose `alg` is not the key's identifier as a string -
  including the polymorphic `EdDSA` - is refused.
- **`VerifyReport` gains `unchecked` and `complete`** (§11.4), so a caller that only reads `ok` cannot
  mistake an unchecked signature for a verified one.
- **An attempt for an operation that has concluded is refused (§7.1 rule 4).** Where its `session_id`
  and `id` already have a sealed outcome, the host rejects it as `replay-detected`, so no attempt is
  sealed after its own terminal record; a byte-identical repeat of a sealed attempt is still answered
  from the ledger. The verifier likewise correlates an outcome, and accounts for a refusal, only by an
  attempt sealed before it.

### Added

- **Round affinity over Streamable HTTP (§6.4, §10.11, §11.2, §11.3).** `auditable-mcp-sdk/mcp/http`
  is the tool's HTTP entry for MCP 2026-07-28: `createAuditableMcpHandler(factory, options)` wraps the
  official `createMcpHandler` and serves each audited `tools/call`, and its retries, from a connection of
  its own in memory behind the existing seam, after the official handler's own validation; everything
  else goes to the official handler. It checks `Auditable-Mcp-Session` against the body (`400`,
  `-32020`), optionally `Origin` and `Host`, binds a held call to its opener's principal when
  `principalOf` is given, and forwards a retry whose round another instance holds through `forward`
  (`fetchForwarder({ resolve })`, marked `Auditable-Mcp-Forwarded: 1`, never forwarded twice); what it
  can neither serve nor forward it refuses as a replay, performing nothing. `toNodeListener` (in
  `auditable-mcp-sdk/node`) serves it from `node:http`. `@modelcontextprotocol/server` is an optional
  peer dependency (`~2.1.0`, the tested minor), needed only by this entry point.
- **Every round names its instance, and a retry is never a first request.** The HTTP entry replaces the
  `requestState` of the tool's own input rounds with an `amcp.<instance>.<random>` token and gives it
  back on the retry, so those retries route and forward like the seam's. A request that carries a
  `requestState` for a session not held is refused, never opened; a second opening of a held session is
  refused with `this session is already open (§6.3)`. Only a held call with nothing under way (no
  request in flight, no running handler, no accepted operation without its outcome) is evicted.
  Forwarding runs after the official validation; a forward that fails after it was sent is answered
  `-32603` `forwarding failed after the retry was sent; its outcome is unknown (§6.4)` rather than as a
  replay (`ForwardNotDeliveredError` marks the provably undelivered case, and `fetchForwarder` does not
  follow redirects). A failing factory is answered in-band. `-32020` and `-32021` are HTTP 400 on the
  audited path. A held call's handler reads the request it is served under now from `call.request` and
  `authInfoOf(call)`. The seam refuses to send a JSON-RPC batch.
- **One lifetime rule for held calls.** A running call (handler running, or an accepted operation without
  its outcome) is neither evicted nor expired; an undelivered one (outcomes or a final frame the host has
  not received) is not evicted but does expire after `idleTimeoutMs`; any other is evicted least recently
  used first and expires. An accept that arrives after its attempt was answered `unavailable` does not make
  the call running. A retry of the tool's own round under no session, or another, is refused without
  consuming the round. A forwarded SSE answer that breaks mid-stream ends with an SSE event carrying the
  unknown-outcome error rather than a broken connection.
- **The host carries the affinity header.** `McpAuditReceiver` sets `Auditable-Mcp-Session` on the
  opening `tools/call` of an audited call and on every retry, and each retry it sends repeats the
  per-request headers of the request it repeats (`Mcp-Param-*`) and its cancellation signal. A client
  that cancels a call on a per-request-stream transport ends its audit session (§6.3). A retry that
  cannot be sent ends the call with a JSON-RPC error to the client.
- **Round tokens name their instance**: `amcp.<instance>.<43 base64url characters of 32 random
  bytes>`, the form both SDKs mint. `McpAuditTransport` takes `instance` (default: 16 random bytes,
  base64url, per process). `AFFINITY_HEADER`, `FORWARDED_HEADER`, `instanceOfToken`, `mintRoundToken`
  and `newInstanceId` are exported from `auditable-mcp-sdk/mcp`. `McpTransport.send` admits the array
  form, so the official `StreamableHTTPClientTransport` fits `McpAuditReceiver` without a cast.
- **The walk runs over HTTP** with `WALK_TRANSPORT=http`, through the HTTP entry and the official
  `StreamableHTTPClientTransport`.

- **The countersignature (§5.2).** `AuditHost` takes a `countersigner` (`Ed25519Countersigner`
  locally, `AwsKmsCountersigner` through KMS) and signs `{host_ts, log_id, previous_hash, record_hash,
  seq}` of every record it seals. The accept carries `host_signature`, `host_key_id` and `log_id`
  together, and `SealedRecord` stores them. `AmcpSession` takes a `countersignatureVerifier`
  (`CountersignatureRegistryVerifier`) and enforces §7.2's precedence: status, then the
  countersignature, then the hash.
- **The MCP wire binding** (`auditable-mcp-sdk/mcp`), in both of §6's forms. Under MCP 2026-07-28 the
  exchange rides the `tools/call` as Multi Round-Trip Requests (§6.4); under the `initialize` handshake
  it is `audit/attempt` and `audit/outcome` (§6.5). `McpAuditTransport` hands the handler one
  `McpAuditCall` per `tools/call`; `McpAuditReceiver` issues the session, seals what comes back, and
  closes the session when the call ends. The seams declare the extension in whichever handshake
  arrives and read the peer's back. The §6.4 seam keeps the suspended handler in the process and does
  not serialize it into `requestState`; round affinity (above) is how a retry reaches it over HTTP. The
  entry point declares the MCP transport surface structurally, so it adds no dependency.
- **`transportFor`** picks what §6.2 permits for a call that was not negotiated, and refuses to return
  a transport for the third, non-conformant posture. `UnnegotiatedCallError` is what it throws.
- **Atomic sealing (§7.1).** One lock per partition across validation, sealing and commit, so
  concurrent attempts take distinct positions in the chain.
- **Atomic numbering (§7.4).** One section per session across numbering and emission, so concurrent
  Level-2 actions reach the host in the order they were numbered, whatever the signer's latency.
- **`unresolved-attempt`.** A session closed with an accepted attempt and no terminal outcome is
  flagged on the host.
- **Key exchange (§5.1).** `publicJwk` / `publicKeyOf` / `jwkThumbprint` carry a registry entry as a
  JWK (RFC 7517, 7638) with its role, and `toolKeyPkcs8` / `loadToolKey` carry a tool's private key as
  PKCS#8. `KeyRole` separates tool keys from host keys.
- **AWS KMS signs `ES256` or `Ed25519`**, chosen by the key's spec, and publishes its public keys.
- **`VerifyOptions`** as the last argument of `verifyChain` / `verifyLedger`, for the out-of-band
  inputs of §10.10 and §11.4:
  - `countersignatureRequired`: an uncountersigned record is reported `host-signature-invalid` rather
    than as a state, since a storage-level attacker can strip a countersignature it cannot forge.
  - `expectedIdentity` (`ExpectedIdentity`, `{ logId, hostKeyIds }`): a record whose `log_id` differs,
    whose `host_key_id` is not in the set, or that carries no full countersignature is reported
    `principal-mismatch`. The key is part of the identity because a `log_id` is distinct only among one
    host's chains. The check runs for a record that cannot be canonicalized as well.
- **`unaccountedSignerSeq`** (§11.4): the verifier's accounting of a session's missing numbers, reported as maximal runs (`first`, `last`) computed from the gaps between sealed values, so a value near 2^53 costs one entry. Sealed aborted refusals account for values.
- **`AmcpUsageError`** separates an integrator error from a transport fault, so the binding's own
  refusals are not filed as `host-unavailable`.
- **`auditable-mcp-sdk/reasons`** is an entry point for the Tier-1 vocabulary, as `auditable_mcp.reasons`
  is in the Python port.
- `auditRequestMetaSchema` / `auditResultMetaSchema` (the §6.4 `_meta` objects);
  `countersignaturePayload`; `verifyDetachedSignature`; `UNRESOLVED_ATTEMPT`, `HOST_UNCOUNTERSIGNED`
  and `HOST_SIGNATURE_INVALID`.

- **The official MCP transports fit the seams without casts.** `McpAuditTransport` and
  `McpAuditReceiver` take a `StdioServerTransport` / `StdioClientTransport`, and are accepted by
  `serveStdio` and `Client.connect`, under `exactOptionalPropertyTypes`; the MCP packages remain type-free
  of the entry point.
- **`verifyLedger` / `verifyChain` take an options object** (`VerifyLedgerOptions`) beside the
  positional form, and refuse a verifier object passed where a checker function belongs with an
  `AmcpUsageError` naming the method to pass.
- **`AuditHost.resume` records `unresolved-attempt`** for every sealed attempt without a terminal
  outcome, since a restart ends every call that was in flight (§6.3).
- **`McpAuditReceiver` warns once per connection** when the tool's declaration is missing or does not
  meet the host's requirement, so a host that requires Level 2 does not get an unaudited call silently.
- **`McpAuditTransport.call` takes the raw JSON-RPC id** (`ctx.mcpReq.id`) and matches it by type and
  value, so `1` and `"1"` are two calls and neither is audited as the other; a string form of a number id
  is refused with an error that says so.

- **`McpAuditReceiver` bounds its own wait on the endpoint** (`requestTimeoutMs`, 30 s by default) and answers
  an attempt the endpoint has not decided by then `unavailable`, and delivers a call's final result to
  the client without waiting on the audit work queued for the session. A stalled audit subsystem no
  longer holds a call's result, or, under §6.4, loses it past the tool's own bound.

### Fixed

- **An attempt the binding already answered `unavailable` records nothing.** `AuditEndpoint.handleAttempt` takes a `deadline`, the time after
  which the receiver has answered the tool; `AuditHost` answers an attempt it takes up after that
  `unavailable` without recording it. A stalled audit subsystem no longer seals, or refuses as
  `replay-detected` against a closed session, an attempt the tool was told was not recorded; the tool's
  `aborted` refusal is the ledger's record of it.
- **`AwsKmsVerifier.fromKms` reads the key spec**, verifying an `ECC_NIST_EDWARDS25519` key as `Ed25519`
  rather than registering every KMS key as `ES256`.
- **Usage errors surface at construction.** An `AmcpSession` session id that is not a lowercase UUID, and
  a registry algorithm outside `SignatureAlgorithm`, are refused where they are given.
- **The body's error is never replaced by the terminal outcome's.** A throwing disposer no longer
  reaches the caller as a `SuppressedError` wrapping the body's own error. An outcome has no response
  channel (§6), so losing one is a completeness gap the host resolves (§10.8); it is logged, not thrown.
- **A tool-side failure is not reported as the host's.** A signer that fails reaches the caller as
  itself rather than as `AmcpAbortedError(host-unavailable)`.
- **Every abort path emits best-effort**, so a failure while recording the abort does not replace why
  the tool stopped (§7.2).
- **A registry compares keys, not encodings.** §5.1 admits both SEC1 forms of a P-256 point, so the
  compressed and uncompressed encodings of one key are the same key, and re-registering it is the
  idempotent case §10.9 permits.
- **`McpAuditReceiver` bounds a §6.4 round by one deadline** (`requestTimeoutMs` from when the round is
  taken up), not one per attempt. Its items are still processed in array order; an attempt reached after
  the deadline is answered `unavailable` without reaching the endpoint, one being decided is answered
  `unavailable` while its decision goes on, and outcomes not yet sealed are sealed after the retry, in
  the session's queue. The retry - or the round passed up to the client - goes at the deadline at the
  latest; the round-limit and missing-`requestState` paths follow the same rule. A round of N stalled
  attempts took N timeouts, and a slow outcome seal held the retry, long enough for the tool to drop the
  call's result.
- **`McpAuditReceiver` removes this extension's member from results it passes to the client** - final
  results and rounds that ask the client for input - and removes a `_meta` it leaves empty (§6.4).
- **`McpAuditReceiver` closes every session on close, bounded.** The configured `requestTimeoutMs`
  replaces the 30 s default in the close path and in how long an ended call's late answer is dropped.
  The sessions of concluding calls, whose seals are still queued, are closed too; work still queued
  when the bound expires is logged with its session id.
- **`McpAuditReceiver` bounds the rounds it holds for the client's retry** at `MAX_IDLE_SESSIONS`,
  evicting the least recently held with a warning and closing its session, and finds a held round by
  its `requestState` without scanning the calls in flight.
- **`McpAuditTransport` keeps a call that concluded while a round was out until that round's retry**,
  however late, and answers it with the final result and its trailing outcomes, or the outcomes-only
  round and then the error (§6.4). The final frame was dropped one request timeout after the handler
  concluded. Kept calls are bounded by `MAX_IDLE_SESSIONS` (least recently kept evicted, with a
  warning) and the connection's lifetime.
- **Revocation survives a JWK Set round trip (§10.9).** `toJwks` marks a revoked entry
  `amcp_revoked: true` (`REVOKED_MEMBER`), `publicJwk` / `publicKeyOf` carry it, and `loadJwks` holds
  such an entry revoked. Loading an unrevoked copy of a key already revoked does not unrevoke it.
- **The AWS KMS adapter's documentation matches it.** The README builds the signer with
  `AwsKmsSigner.fromKms`, which reads the algorithm from the key; the constructor defaults to ECDSA
  P-256, which KMS refuses for an Ed25519 key. `loadKmsPublicKey` returns the raw public key of either
  algorithm (65-byte P-256 point or 32-byte Ed25519 key) and refuses a key spec §5.1 does not define;
  `kmsRegistryEntry` remains the form that carries the algorithm.

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
