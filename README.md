# Auditable MCP SDK (TypeScript)

A protocol machine for [Auditable MCP](https://github.com/SatoshiImai/mcp-audit-extension)
(`auditable-mcp/0.3`). It lets an MCP tool self-attest its internal domain operations (SQL queries,
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
- The MCP wire binding, both of §6's: the exchange carried on the `tools/call` itself as Multi
  Round-Trip Requests under MCP 2026-07-28 (§6.4), and `audit/attempt` / `audit/outcome` under the
  `initialize` handshake (§6.5). Which one a call uses is read from the call.
- Audit sessions (§6.3): the host issues one per `tools/call`, and every event of the call carries it.
- The countersign: a host that declares it signs, signing what it sealed, and the tool and verifier
  checking it.
- Ed25519 / ES256 signing and verification, plus an AWS KMS adapter, behind an injectable crypto engine. The
  default engine is universal (noble); a `node:crypto` engine ships as a drop-in alternative.
- The durable-ledger lifecycle — seal-before-accept, fail-closed on a persistence error, and
  resume-after-restart — over a `LedgerRepository` interface you implement.
- Atomic sealing (§7.1): one lock per partition, so concurrent attempts take distinct positions in
  the chain rather than the same one.
- Atomic numbering (§7.4): `signer_seq` counts from zero in each session, and one section per session
  makes concurrent Level-2 actions reach the host in the order they were numbered rather than the
  order their signing finished in. Nothing about the count outlives the call, so there is nothing to
  store or share between processes.

What it does not do (your concern, via adapters):

- No storage backend. The SDK defines the `LedgerRepository` interface (with an in-memory
  implementation for tests); you implement it over your store. A `SealedRecord` is plain JSON.
- No transport lock-in. The core defines an abstract transport and bundles the in-process one. The
  MCP wire binding is a separate entry point (`auditable-mcp-sdk/mcp`) that declares the transport
  surface structurally, so importing it pulls in no MCP package either.
- No tool business logic, and no in-process private keys in production — sign through a KMS/HSM.

## Status

Alpha, tracking `auditable-mcp/0.3`. The public API is unstable while the spec is a pre-1.0 draft.

## Install

```bash
npm install auditable-mcp-sdk
```

ESM-only. Requires Node.js 20+ (the core is runtime-agnostic and also runs on browsers, Deno, and
edge runtimes). Entry points:

| Import                          | Contents                                                        |
| ------------------------------- | --------------------------------------------------------------- |
| `auditable-mcp-sdk`             | The runtime-agnostic core (session, host, L2, verify, storage)  |
| `auditable-mcp-sdk/mcp`         | The §6 wire binding on a real MCP connection (§6.4, §6.5)       |
| `auditable-mcp-sdk/mcp/http`    | The tool's Streamable HTTP entry with round affinity (§6.4); needs `@modelcontextprotocol/server` |
| `auditable-mcp-sdk/reasons`     | The Tier-1 reason and anomaly vocabulary (§7.6, §12.2)          |
| `auditable-mcp-sdk/node`        | Node adapters: ambient session (`AsyncLocalStorage`), `node:crypto` engine, `toNodeListener` |
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
  same process; `auditable-mcp-sdk/mcp` carries the same seam over a real MCP connection.
- Sessions: an audit session is one `tools/call` (§6.3). The host issues its id, closes it when the
  call ends, and flags any attempt the call left without an outcome (`unresolved-attempt`).
- Levels: Level 1 is self-reporting; Level 2 adds a detached signature and a per-session sequence. The
  only difference on the tool side is an injected signer, and on the host side an injected verifier.
- Countersign: an independent axis (§5.2). The level says how strongly a tool's attestation resists
  forgery; the countersign says who sealed it. A host that declares `countersign: "host"` signs the
  host-assigned fields of every record it seals, together with the `log_id` that names its chain, so
  a verifier can tell a chain a distinct host confirmed from one a tool recorded for itself. Absence
  of a countersignature is a state, not an anomaly.
- Degradation: a tool that speaks this extension stays usable by hosts that do not. Where the
  extension was not negotiated, `transportFor` gives back either an audit host the tool provides for
  itself (degraded) or refuses to serve (mandatory) — and refuses to return anything at all for the
  third, non-conformant posture of serving while recording nothing (§6.2).

## Quickstart

### 1. Level 1, in-process

```ts
import { AmcpSession, AuditHost, InProcessTransport, verifyLedger, withAudit } from 'auditable-mcp-sdk';

const host = new AuditHost('tenant-a'); // Level 1 by default

// One audit session per call (§6.3): the host issues it and closes it when the body returns.
const rows = await host.withSession(async (sessionId) => {
  const session = new AmcpSession(new InProcessTransport(host), sessionId);
  return withAudit(
    session,
    {
      actionType: 'db.query',
      targetResource: { kind: 'database', ref: 'analytics-postgres' },
      mutates: false,
      egress: false,
      disclose: { dialect: 'postgres' }, // optional cleartext context
      commit: { sql: 'SELECT id FROM users' }, // optional hash commitment
    },
    () => runTheQuery(),
  );
});

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
    { mutates: false, egress: false },
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
  Ed25519Signer,
  generateToolKey,
  InProcessTransport,
  KeyRegistry,
  KeyRegistryVerifier,
} from 'auditable-mcp-sdk';

const toolKey = generateToolKey('tool-1');

const registry = new KeyRegistry(); // the host's out-of-band trust anchor
registry.registerToolKey(toolKey); // binds the key_id to Ed25519 (§5.1)

const host = new AuditHost('tenant-a', { level: 'L2' }, {
  verifier: new KeyRegistryVerifier(registry),
});
const sessionId = host.openSession();
const session = new AmcpSession(new InProcessTransport(host), sessionId, {
  signer: Ed25519Signer.fromToolKey(toolKey),
});
// ... run the call's actions, then:
await host.closeSession(sessionId);
```

One `KeyRegistryVerifier` handles a heterogeneous fleet: the algorithm (`Ed25519` or
`ES256`) is bound to each `key_id` in the registry (§5.1), not carried in the event. The
default crypto engine is universal (noble); pass the Node engine
(`Ed25519Signer.fromToolKey(toolKey, { engine: nodeEd25519Engine })` from `auditable-mcp-sdk/node`)
to use the platform crypto instead.

### 5. Level 2 with AWS KMS (production)

The private key never leaves KMS. The signer calls `kms:Sign`; the verifier fetches the public key
once at onboarding and verifies locally. The default is ECDSA P-256 (`ECDSA_SHA_256`, JOSE `ES256`)
on an `ECC_NIST_P256` key; an `ECC_NIST_EDWARDS25519` key signs `Ed25519`. `AwsKmsCountersigner`
does the same for a host's countersignature. The adapter takes an injected client and never imports
an AWS SDK, so you adapt your `@aws-sdk/client-kms` client to the small `KmsClient` interface.

```ts
import { AmcpSession, AuditHost, InProcessTransport } from 'auditable-mcp-sdk';
import { AwsKmsSigner, AwsKmsVerifier } from 'auditable-mcp-sdk/aws-kms';

const signer = await AwsKmsSigner.fromKms(kms, keyArn, { eventKeyId: 'tool-1' });
const verifier = await AwsKmsVerifier.fromKms(kms, { 'tool-1': keyArn });

const host = new AuditHost('tenant-a', { level: 'L2', attempt: 'request' }, { verifier });
await host.withSession(async (sessionId) => {
  const session = new AmcpSession(new InProcessTransport(host), sessionId, { signer });
  // ... the call's actions
});
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

### 8. Over a real MCP connection

Neither official MCP SDK can deliver this extension through its own dispatch, and neither has to:
everything it adds is ordinary JSON-RPC on the connection MCP already holds, and a `Transport` is
something you hand to the session. The binding wraps the real transport and gives the session a seam
instead. Everything that is not audit traffic passes through untouched, so the session sees exactly
the MCP it would have seen without this extension.

Both bindings are served from the same code. A `tools/call` made under MCP 2026-07-28 carries the
exchange on the call itself (§6.4): the seam ends a round with an `InputRequiredResult` carrying the
events, keeps the handler suspended until the host's retry brings the answers, and puts the handler's
final result on the retry. A call made under the `initialize` handshake uses `audit/attempt` and
`audit/outcome` (§6.5). The handler is written once and never sees the difference.

A tool (an MCP server). The official `Server.connect` serves only the `initialize` era; `serveStdio`
picks the era from the opening message and takes any transport, so the seam goes there. The official
transports and the seams are assignable to each other as they are — no casts:

```ts
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio, StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import {
  AmcpSession,
  type AuditCapability,
  AuditHost,
  Countersign,
  InProcessTransport,
  Level,
  Posture,
  SPEC_VERSION,
  transportFor,
  withAudit,
} from 'auditable-mcp-sdk';
import { McpAuditTransport } from 'auditable-mcp-sdk/mcp';

const TOOL_CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};

// The audit host the tool provides for itself when the call was not negotiated (§6.2).
const selfHosted = new AuditHost('tool-local', TOOL_CAPABILITY);

// The seam declares the extension in the handshake result and reads the host's declaration back.
const audit = new McpAuditTransport(new StdioServerTransport(), TOOL_CAPABILITY);

function buildServer(): McpServer {
  const server = new McpServer({ name: 'customers', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.registerTool('read_customers', { description: 'Read the customer table' }, async (ctx) => {
    const call = audit.call(ctx.mcpReq.id); // the per-call transport for the request being served
    const transport = transportFor(call.negotiate(TOOL_CAPABILITY), {
      negotiated: call,
      fallback: new InProcessTransport(selfHosted),
      posture: Posture.DEGRADED, // the default; Posture.MANDATORY refuses to serve unaudited
    });
    const degraded = transport !== call;
    if (degraded) {
      selfHosted.openSession(call.sessionId); // degraded: the tool is its own host, so it opens the session
    }
    try {
      const rows = await withAudit(
        new AmcpSession(transport, call.sessionId),
        { actionType: 'db.query', targetResource: { kind: 'table', ref: 'customers' }, mutates: false, egress: false },
        () => readCustomers(ctx.mcpReq.signal),
      );
      return { content: [{ type: 'text', text: rows }] };
    } finally {
      if (degraded) {
        await selfHosted.closeSession(call.sessionId); // ... and closes it when the call ends (§6.3)
      }
    }
  });
  return server;
}

serveStdio(buildServer, { transport: audit });
```

`posture` decides what a call that was not audit-negotiated gets (§6.2): `Posture.DEGRADED` (the
default) records into the `fallback` host the tool provides for itself; `Posture.MANDATORY` throws
`UnnegotiatedCallError` and the tool does not serve. A tool that requires a countersignature cannot
degrade — its own host holds no key a verifier binds to a host — so `transportFor` refuses the
degraded posture for it: use `Posture.MANDATORY`.

A countersign on the tool side takes **both** halves: the capability declares `countersign: 'host'`
(so the host is asked to countersign), **and** the `AmcpSession` is built with
`{ requireCountersign: true, countersignatureVerifier: new CountersignatureRegistryVerifier(hostRegistry) }`
(so the tool checks it before it acts). Either alone does not make the tool refuse an uncountersigned
accept.

`audit.call(id)` takes the raw JSON-RPC id the request carried (`ctx.mcpReq.id`). Ids are matched by
type and value, so `1` and `"1"` are two calls and neither is audited as the other; a string form of a
number id is refused with an `UnknownCallError` that says to pass the raw id.

The per-call transport (`McpAuditCall`):

| Member | Meaning |
| --- | --- |
| `negotiate(offered)` | Compare the host's declaration for this call with the tool's (§6.1) and open the send path. `offered` must be what the seam declared. Under §6.5 it throws `HandshakeNotSeenError` before `initialize` |
| `sessionId` | The audit session every event of the call carries: the host's when negotiated, else one minted for the degraded posture (§6.3) |
| `numbering` | The call's `signer_seq` numbering (§7.4), shared by every `AmcpSession` over the call |
| `hostCapability` | What the host declared for this call, or `undefined` |

`new McpAuditTransport(inner, capability, { requestTimeoutMs, instance })` bounds the wait for each
decision; `requestTimeoutMs` defaults to `DEFAULT_REQUEST_TIMEOUT_MS` (30 000), and an attempt not
answered in time is `unavailable` (fail closed). `instance` is the name its round tokens carry
(`amcp.<instance>.<random>`, `[A-Za-z0-9_-]{1,64}`), by default one drawn at random for the process. Two further bounds are fixed: a host follows at most
`MAX_ROUNDS_PER_CALL` (256) §6.4 rounds in one call, and a tool keeps at most `MAX_IDLE_SESSIONS`
(1024) idle audit sessions per connection.

A host (an MCP client) wraps its own transport around its `AuditHost`, and its declaration is the
host's requirement itself — there is no second copy to drift. The receiver issues an audit session in
each outgoing `tools/call`, answers a round that asks the client for nothing else by retrying on the
spot, passes a round that also carries `inputRequests` up to the client with the audit answers riding
its retry, and closes the session when the call ends:

```ts
import { capabilityOf, McpAuditReceiver } from 'auditable-mcp-sdk/mcp';

const audit = new McpAuditReceiver(new StdioClientTransport(params), host);
const client = new Client(info, { versionNegotiation: { mode: { pin: '2026-07-28' } } }); // omit for `initialize`
await client.connect(audit);
const toolCapability = capabilityOf(client.getServerCapabilities()); // undefined = an ordinary MCP tool
```

The receiver does not refuse a tool whose declaration is absent or does not meet the host's
requirement — whether an unaudited tool may be called is the host's decision. It logs one
`console.warn` per connection naming the §6.1 outcome (`undeclared` or `mismatch`), and the host
should check `capabilityOf(client.getServerCapabilities())` against its requirement (`negotiate`) and
decide before it calls a tool.

§6 obligations that live in this entry point and nowhere else: the wait for a decision is bounded and
fails closed when it expires; every `requestState` the seam issues starts with `amcp.`, and one that
names no open round is refused with a JSON-RPC error, so a replayed retry never runs an operation twice;
and nothing at all is sent on a call that was not audit-negotiated.

The §6.4 seam keeps the suspended handler in the process that serves the call and does not serialize
it into `requestState`; the specification leaves that mechanism to the implementation. Over stdio every
retry comes back on the same connection. Over Streamable HTTP, where each request is a POST of its own,
see [Over Streamable HTTP](#9-over-streamable-http-round-affinity).

The `amcp.` prefix is reserved for the seam's own rounds. A tool that runs its own `inputRequests`
rounds must not give its own `requestState` a value that starts with `amcp.`: the seam would take the
client's retry for one of its own rounds and refuse it as a replay. The seam logs an error when a
handler's `input_required` result carries such a state.

A call whose handler answers with its own `input_required` stays open on the tool until the client
retries it: its audit session, with the host's declaration and the `signer_seq` numbering, is kept idle
until the connection closes. Beyond MAX_IDLE_SESSIONS idle sessions per connection the least recently idle one is evicted with a warning. A retry of an evicted session starts a fresh record: under Level 2 its numbering restarts and the host refuses the repeated values (fail-closed); under Level 1 the retry negotiates again under the same session_id.

### 9. Over Streamable HTTP (round affinity)

Under MCP 2026-07-28 the official Streamable HTTP handler serves each POST statelessly, so there is no
connection for the seam to wrap and nothing to keep a suspended handler in. `auditable-mcp-sdk/mcp/http`
is the tool's HTTP entry: it wraps the official handler (`createMcpHandler`) and takes over only the
`tools/call` requests of audited calls - one whose `_meta` carries this extension's `session_id` opens a
call, and one that also carries a `requestState` (or carries one of this entry's `amcp.` tokens) is a
retry. Each audited call gets a connection of its own in memory, with the tool's server from your factory
on it behind the same seam as over stdio; every POST of the call is written into it and answered with
what it answers. Everything else - `server/discover`, `tools/list`, unaudited calls, 2025-era traffic -
goes to the official handler untouched, served behind a seam of its own, so an unaudited call degrades
(or is refused) exactly as on any other transport.

```ts
import { createServer } from 'node:http';
import { authInfoOf, createAuditableMcpHandler, fetchForwarder } from 'auditable-mcp-sdk/mcp/http';
import { toNodeListener } from 'auditable-mcp-sdk/node';

// The factory takes the seam its server is served behind; handlers use `audit.call(ctx.mcpReq.id)` as over stdio.
const handler = createAuditableMcpHandler((audit) => buildServer(audit), { declares: TOOL_CAPABILITY });
createServer(toNodeListener(handler)).listen(8080); // or `handler.fetch` on a fetch-native runtime
```

A taken-over request passes the official handler's validation first - `MCP-Protocol-Version`,
`Mcp-Method`, `Mcp-Name`, every `Mcp-Param-*` against the tool's `x-mcp-header` declarations, client
capabilities, content type, body size - because it is dispatched through that handler into a server
from your factory whose `tools/call` serves it from the held connection, or forwards it. The response
mode is the official `responseMode` (default `auto`: JSON, or SSE when the tool sends a notification such
as progress before the round ends). What the official handler does not check is checked here:
`Auditable-Mcp-Session` against the body, and, when `allowedOrigins` / `allowedHosts` are given, `Origin`
and `Host` on every request. Closing an HTTP request cancels the call it carries (§6.3); the tool's
handler sees `ctx.mcpReq.signal` abort.

A held call's handler reads the request it is being served under now - the one that opened the call, and
after each round the retry that resumed it - from its call: `call.request` (the HTTP `Request`) and
`authInfoOf(call)` (the `authInfo` passed to `fetch`). `ctx.http.authInfo` is not set inside a held
call; the factory's context carries the opener's. The Python SDK exposes the same accessor for its held
calls, since a resumed Python handler keeps the context variables of the request that invoked it: in
both SDKs, read the per-request request and authentication through the call.

**How long a held call lives.** One rule, the same in both SDKs:

| State of the held call | Closed to make room (`maxHeldCalls`) | Closed after `idleTimeoutMs` with no request in flight |
| --- | --- | --- |
| **running**: its handler runs outside a wait for a retry, or an operation the host accepted has no outcome yet | never | never - an accepted operation is not cancelled mid-flight, whose outcome could not be known; it becomes eligible once it stops running |
| **undelivered**: it holds outcomes or a final frame the host has not received | never | yes - the host has had `idleTimeoutMs` to retry, and its session end records what is missing |
| neither | yes, least recently used first | yes |

When no held call can be closed, a new audited call is refused (`-32603`). Filling the registry with
running calls takes the host's accepts; where untrusted clients can reach the tool, require a
countersignature (§5.2), so that only the host you trust can accept, and set `principalOf`.

**Status codes.** Refusals on the audited path (a replay, another principal, a second opening of a held
session, a full registry, an unknown forwarding outcome) and a tool's own JSON-RPC errors are answered
in-band, with HTTP 200 and a JSON-RPC error, as the official handler answers a handler's error. `-32020`
(`HeaderMismatch`) and `-32021` (a missing client capability) are HTTP 400 wherever they arise.

**Round affinity.** Every request of an audited call carries `Auditable-Mcp-Session: <session_id>`
(§6.4): `McpAuditReceiver` sets it on the opening `tools/call` and on every retry, and each retry also
repeats the request metadata headers of the request it repeats (`Mcp-Param-*`; the transport derives
`Mcp-Method` and `Mcp-Name` from the body). The body is the source of truth: the entry answers a header
that is absent while the body carries a `session_id`, present while it carries none, or different, with
HTTP `400` and `-32020` (`HeaderMismatch`). An intermediary must pass the header through unchanged. With
more than one instance, every retry of a call has to reach the instance that holds it. Either:

- route on the header - any load balancer that hashes `Auditable-Mcp-Session` keeps a call on one
  instance - or
- forward: give each instance a name (`instance`) and a `forward`. Every round of an audited call is
  answered with a `requestState` that names the instance holding it (`amcp.<instance>.<random>`): the
  seam's own rounds, and the tool's own input rounds too, whose `requestState` the entry replaces with such
  a token and gives back to the tool on the retry. That replacement is what lets forwarding alone carry
  the tool's own rounds. An instance that receives a retry it does not hold forwards it there, after
  validating it, and relays the owner's response.

```ts
const peers = new Map([['tool-a', 'http://10.0.0.11:8080/mcp'], ['tool-b', 'http://10.0.0.12:8080/mcp']]);
const handler = createAuditableMcpHandler(factory, {
  declares: TOOL_CAPABILITY,
  instance: 'tool-a',
  forward: fetchForwarder({ resolve: (instance) => peers.get(instance) }), // only instances you registered
  principalOf: (_request, authInfo) => authInfo?.clientId, // bind each call to its opener
  allowedHosts: ['tool.example.com', '10.0.0.11', '10.0.0.12'], // include the hosts peers forward to
});
```

**Give it `principalOf`.** A `session_id` travels in a header that load balancers and proxies may log,
and a round token travels to the client; with `principalOf` a retry that another principal presents is
refused, performing nothing, whoever learned them. When `allowedHosts` is set, it must include the
internal hosts other instances forward to, or every forward is refused with `403`.

**The forwarder's read timeout must be unbounded**, or longer than any operation the tool performs. A
forward is refused as a replay only when it provably never reached the owner - the resolver does not know
the instance or throws, the connection could not be made, or the owner answered with a redirect
(`fetchForwarder` does not follow redirects). A forward that fails after it was sent - a timeout, a reset,
a body cut short - may have been performed by the owner, and is answered with `-32603` `forwarding
failed after the retry was sent; its outcome is unknown (§6.4)` (an SSE answer that breaks after it began
ends with an SSE event carrying that error, as the Python SDK's does); a custom `forward` that throws anything
but `ForwardNotDeliveredError` is answered the same way.

What still fails closed, performing nothing: a retry whose round this instance does not hold when there
is no `forward`, when the token names this instance or no instance, when the forward was provably not
delivered, or when the request was itself forwarded (`Auditable-Mcp-Forwarded: 1`, which the forwarder
sets and which is never forwarded again, so a forward cannot loop); a replayed or forged token; a
`requestState` on a request for a session this instance does not hold, which is never served as a call's
first request; a retry of a call closed for being idle longer than `idleTimeoutMs`
(`DEFAULT_IDLE_TIMEOUT_MS`, 10 minutes) or evicted beyond `maxHeldCalls` (`MAX_IDLE_SESSIONS`), under the
lifetime rule above; a retry of the tool's own round under no session or another; and a retry of a held
call that `principalOf` says another principal sent. Each is refused with the JSON-RPC error `this requestState names no open round (§6.4)` (or
one that names the principal), the same way a replay is. A request without `requestState` for a session
already held is refused with `this session is already open (§6.3)`: the host issues a fresh session for
every call. The instance name in a token only selects among the instances your resolver returns; the
random part is what finds the held call, and a client cannot guess it.

### Notes

- `host.anomalies()` is held in memory and is not persisted. `AuditHost.resume` recomputes the one
  anomaly a restart causes — every sealed attempt with no sealed terminal outcome after it is
  `unresolved-attempt`, and its session is not reopened — but everything else flagged before the
  restart is gone. Persist `anomalies()` yourself if you need it across restarts.
- After a resume, verify the full persisted chain (`verifyLedger(await repo.readAll(partition), ...)`),
  not `host.records()`: the resumed host holds only what it sealed since, and a window that starts
  mid-chain verifies as broken.
- A client's cancellation ends the call and its audit session, but it does not interrupt the audited
  body. Pass `ctx.mcpReq.signal` into your own work if it should stop.

### Limitations

- Logging goes to `console.*` (`error`, `warn`, `debug`); there is no pluggable logger yet. Route the
  console if you need the messages elsewhere.

### The walk

`npm run walk` runs the SDK the way a deployment does: the tool is a **separate process**, the wire
is a real pipe, and the host is the official MCP client with an `McpAuditReceiver` in front of it.
The suite cannot see what only exists across that boundary — framing, back-pressure, process
lifetime, and operations that really are concurrent — so the walk covers it, and each case states
what it expects of the ledger rather than of the SDK's internals.

It also drives the **Python** tool from this host, while the Python SDK's `walk/run.py` drives this
SDK's tool from its own. Between them both bindings meet the other port's on a real wire, in both
combinations, which is where the interoperability claim is checked rather than asserted. Those cases
are skipped if the other port is not checked out beside this one.

Every case runs under both bindings, §6.4 and §6.5. The cases have teeth: removing the §7.1 sealing
lock, the §7.4 numbering section, or either side's handshake declaration turns the walk red. Guards against *misuse* of this SDK's own API are not
covered here — nothing across a process boundary can provoke them — and belong to the suite.

```bash
npm run walk              # every case
npm run walk crosslang    # the cross-language cases
WALK_TRANSPORT=http npm run walk   # the MCP 2026-07-28 cases over Streamable HTTP, through the HTTP entry
```

Over HTTP the tool process serves through `auditable-mcp-sdk/mcp/http` on an ephemeral port and writes
one stdout line, `WALK_HTTP_URL=<url>`; the host connects with the official
`StreamableHTTPClientTransport`. The `initialize` cases stay on stdio. The Python tool is driven over
HTTP by the same contract. The cross-language cases use the Python checkout beside this one
(`auditable-mcp-sdk-python`, or `auditable-mcp-sdk-python-<suffix>` for a worktree
`auditable-mcp-sdk-ts-<suffix>`; `WALK_PY_REPO` overrides it) and the interpreter that imports that
checkout's own `auditable_mcp` (`WALK_PYTHON` overrides it), so a worktree never runs another checkout's
code.

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

## Note on AI Assistance

The core architecture, design decisions, and core implementations in this project are entirely my own. I used AI tools (Claude, Gemini) strictly under my explicit direction for code generation, text formatting, edge-case verification, and polishing my English prose. All outputs were heavily reviewed, corrected, and finalized by me.

## License

MIT (c) Satoshi Imai
