# Auditable MCP SDK (TypeScript)

A protocol machine for [Auditable MCP](https://github.com/SatoshiImai/mcp-audit-extension)
(`auditable-mcp/0.1`). It lets an MCP tool self-attest its internal domain operations (SQL queries,
downstream API calls) and lets a host seal those attestations into a tamper-evident, hash-chained
ledger.

This is a real SDK, not a demo. It solves only the protocol problem — canonicalization, hashing,
signing, sequencing, state transitions — and leaves storage, transport, crypto, and tool logic to
you, behind explicit injection seams. It is the TypeScript counterpart of the Python SDK and shares
its normative spec and golden vectors, so both reproduce the same canonical bytes and hashes.

## Scope

What this SDK does:

- RFC 8785 (JCS) canonicalization with the strict numeric domain of the spec. Because JavaScript has
  only IEEE-754 numbers, the numeric guard fails closed before canonicalization, so a value that has
  already lost precision can never be sealed into the chain.
- The record-hash preimage and the per-partition hash chain.
- The audit-before-act tool lifecycle and the host audit subsystem (Level 1 and Level 2).
- Ed25519 signing/verification, plus an AWS KMS adapter, behind an injectable crypto engine. The
  default engine is universal (noble); a `node:crypto` engine ships as a drop-in alternative.
- The durable-ledger lifecycle — seal-before-accept, fail-closed on a persistence error, and
  resume-after-restart — over a `LedgerRepository` interface you implement.

What it does not do (your concern, via adapters):

- No storage backend. The SDK defines the `LedgerRepository` interface (with an in-memory
  implementation for tests); you implement it over your store. A `SealedRecord` is plain JSON.
- No transport lock-in. The core defines an abstract transport and bundles the in-process one; you
  wire the `AuditTransport` seam over MCP, importing the official MCP package alongside this one.
- No tool business logic, and no in-process private keys in production — sign through a KMS/HSM.

## Status

Alpha, tracking `auditable-mcp/0.1`. The public API is unstable until v0.1 is tagged.

## Install

```bash
npm install auditable-mcp-sdk
```

ESM-only. Requires Node.js 20+ (the core is runtime-agnostic and also runs on browsers, Deno, and
edge runtimes). Entry points:

| Import                          | Contents                                                        |
| ------------------------------- | --------------------------------------------------------------- |
| `auditable-mcp-sdk`             | The runtime-agnostic core (session, host, L2, verify, storage)  |
| `auditable-mcp-sdk/node`        | Node adapters: ambient session (`AsyncLocalStorage`), `node:crypto` engine |
| `auditable-mcp-sdk/noble`       | The universal default crypto engine (explicit access)           |
| `auditable-mcp-sdk/aws-kms`     | The AWS KMS signer/verifier adapter                             |

## Concepts

- Tool side: an `AmcpSession` wraps each internal operation. The core is `await using`, which enforces
  audit-before-act at the language level: `await session.action(...)` emits the attempt, waits for the
  host to accept, and (under Level 2) runs the Polluted Stop check before the body runs. If the host
  does not accept, `AmcpAbortedError` is thrown and the body never runs. Because a disposer cannot see
  whether the block threw, it fails closed — it records `failed` unless you call `succeeded()`.
- The recommended DX is `withAudit(session, spec, handler)`, which wraps the handler in try/catch and
  restores the automatic success/failed mapping (a returned value is `success`, a throw is `failed`).
  Reach for the bare `await using` primitive only when you want to drive the outcome explicitly.
- Host side: an `AuditHost` validates each event and seals accepted ones into a per-partition,
  hash-chained ledger — in memory, or durably through an injected `LedgerRepository`. It never
  authorizes the domain action; it only protects ledger integrity.
- Transport: the two sides talk over an `AuditTransport`. `InProcessTransport` connects them in the
  same process; a real deployment substitutes a wire transport.
- Levels: Level 1 is self-reporting; Level 2 adds a detached signature and a monotonic sequence. The
  only difference on the tool side is an injected signer, and on the host side an injected verifier.

## Quickstart

### 1. Level 1, in-process

```ts
import { AmcpSession, AuditHost, InProcessTransport, verifyLedger, withAudit } from 'auditable-mcp-sdk';

const host = new AuditHost('tenant-a'); // Level 1 by default
const session = new AmcpSession(new InProcessTransport(host), 'call-1');

const rows = await withAudit(
  session,
  {
    actionType: 'db.query',
    targetResource: { kind: 'database', ref: 'analytics-postgres' },
    mutates: false,
    egress: true,
    disclose: { dialect: 'postgres' }, // optional cleartext context
    commit: { sql: 'SELECT id FROM users' }, // optional hash commitment
  },
  () => runTheQuery(),
);

const report = verifyLedger(host.records(), host.digest());
console.log(report.ok, report.count); // true 2
```

`disclose` and `commit` are both optional. Give neither, either, or both, depending on how much of
the internal context you can safely record.

### 2. The `await using` primitive

Use this when you want to record the outcome yourself. It fails closed: if you do not call
`succeeded()` — because you forgot, or the block threw — the record is `failed`, never a silent
`success`.

```ts
async function query() {
  await using action = await session.action(
    'db.query',
    { kind: 'database', ref: 'analytics-postgres' },
    { mutates: false, egress: true },
  );
  const rows = await runTheQuery(); // if this throws, the disposer records `failed`
  action.succeeded();
  return rows;
}
```

### 3. Handling a refused attempt

When the host rejects the attempt, reports itself unavailable, or the Polluted Stop check fails, the
handler is skipped and `AmcpAbortedError` is thrown. The tool surfaces it as a `tools/call` error.

```ts
import { AmcpAbortedError } from 'auditable-mcp-sdk';

try {
  await withAudit(session, { actionType: 'db.write', targetResource: { kind: 'table', ref: 'orders' }, mutates: true, egress: false }, writeRow);
} catch (error) {
  if (error instanceof AmcpAbortedError) {
    // error.reason is one of: host-rejected, host-unavailable, hash-mismatch
    log.warn(`audit aborted: ${error.reason}`);
  }
}
```

### 4. Level 2 with a local Ed25519 key

Local keys are for development and tests. See the next section for production.

```ts
import {
  AmcpSession,
  AuditHost,
  Ed25519SignatureVerifier,
  Ed25519Signer,
  InProcessTransport,
  KeyRegistry,
  generateToolKey,
} from 'auditable-mcp-sdk';

const toolKey = generateToolKey('tool-1');

const registry = new KeyRegistry(); // the host's out-of-band trust anchor
registry.registerToolKey(toolKey);

const host = new AuditHost('tenant-a', { level: 'L2', attempt: 'request' }, {
  verifier: new Ed25519SignatureVerifier(registry),
});
const session = new AmcpSession(new InProcessTransport(host), 'call-1', {
  signer: Ed25519Signer.fromToolKey(toolKey),
});
```

The default crypto engine is universal (noble). To use the platform crypto instead, pass the Node
engine: `Ed25519Signer.fromToolKey(toolKey, { engine: nodeEd25519Engine })` from `auditable-mcp-sdk/node`.

### 5. Level 2 with AWS KMS (production)

The private key never leaves KMS. The signer calls `kms:Sign`; the verifier fetches the public key
once at onboarding and verifies locally. AWS KMS does not offer Ed25519, so this path uses ECDSA
P-256 (`ECDSA_SHA_256`). The adapter takes an injected client and never imports an AWS SDK, so you
adapt your `@aws-sdk/client-kms` client to the small `KmsClient` interface.

```ts
import { AmcpSession, AuditHost, InProcessTransport } from 'auditable-mcp-sdk';
import { AwsKmsSigner, AwsKmsVerifier } from 'auditable-mcp-sdk/aws-kms';

const signer = new AwsKmsSigner(kms, keyArn, { eventKeyId: 'tool-1' });
const verifier = await AwsKmsVerifier.fromKms(kms, { 'tool-1': keyArn });

const host = new AuditHost('tenant-a', { level: 'L2', attempt: 'request' }, { verifier });
const session = new AmcpSession(new InProcessTransport(host), 'call-1', { signer });
```

The signer and verifier are just the `EventSigner` / `SignatureVerifier` seams; a GCP KMS or HSM
adapter drops into the same place.

### 6. A durable host

The host keeps its chain in memory by default. Inject a `LedgerRepository` to persist every accepted
record before it is acknowledged; a persistence failure then fails closed (`unavailable`). The
bundled `InMemoryLedgerRepository` is for tests — implement the interface over your own store.

```ts
import { AuditHost, InMemoryLedgerRepository, verifyLedger } from 'auditable-mcp-sdk';

const repo = new InMemoryLedgerRepository(); // swap for your own LedgerRepository
let host = new AuditHost('tenant-a', undefined, { repository: repo });
// ... run audited actions; each sealed record is written to `repo` before it is accepted ...

// after a restart, resume the same hash chain (seq, tail link, and replay state are rebuilt):
host = await AuditHost.resume('tenant-a', undefined, { repository: repo });

// audit the full persisted chain, not just this process's records:
const report = verifyLedger(await repo.readAll('tenant-a'), host.digest());
```

### 7. Verifying a ledger

`verifyLedger` recomputes the chain from the record bodies, independent of the stored hashes, and
reports tampering, gaps, broken links, uncorrelated outcomes, and (against an out-of-band anchor)
truncation or rewrite.

```ts
import { verifyLedger } from 'auditable-mcp-sdk';

const report = verifyLedger(host.records(), trustedTailDigest);
if (!report.ok) {
  for (const issue of report.issues) {
    log.error(`ledger issue at seq=${issue.seq}: ${issue.kind} (${issue.detail})`);
  }
}
```

## Conformance

The normative JSON Schema and golden vectors are vendored under [`spec/`](spec/) from the
`mcp-audit-extension` spec repo (their single source of truth), byte-identical to the Python SDK's
copy. A conforming implementation must reproduce every vector byte-for-byte.

```bash
make spec/check    # fail if the vendored spec drifted from source
make test          # includes the cross-language conformance vectors
```

## Development

```bash
make env/init      # install dependencies
make test          # unit + conformance vectors (Vitest)
make lint          # biome check + tsc --noEmit
make build         # bundle ESM + type declarations to dist/
```

## License

MIT (c) Satoshi Imai
