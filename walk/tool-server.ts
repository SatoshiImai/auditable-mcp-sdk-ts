/**
 * An auditable MCP tool, served over real stdio, for the cross-language walk.
 *
 * The mirror of the Python SDK's `walk/tool_server.py`, so one host can drive either and compare
 * what lands in the ledger. That comparison is what §11.1 asks for: given identical inputs,
 * conformant implementations produce an identical `record_hash` across a language boundary. It serves
 * whichever binding the host's call is made under (§6.4, §6.5); the seam reads that from the call.
 *
 * The knobs come from the environment, and the tool key is provisioned out-of-band (§5.1) by the
 * runner, so this process signs with the key the host's registry already holds.
 *
 * `WALK_TRANSPORT=http` serves the same tool over Streamable HTTP through the SDK's HTTP entry, the path
 * a deployed tool takes, on an ephemeral port of 127.0.0.1; the process then writes one line
 * `WALK_HTTP_URL=<url>` to stdout, which is how the runner finds it. MCP 2026-07-28 only (§6.4). It stops
 * on SIGTERM or SIGINT, closing its held calls, and when its stdin ends: the runner keeps that pipe open
 * for the life of the case, so a runner that dies does not leave the tool behind.
 */

import { createServer } from 'node:http';

import { type CallToolResult, McpServer, Server } from '@modelcontextprotocol/server';
import { StdioServerTransport, serveStdio } from '@modelcontextprotocol/server/stdio';
import { base64ToBytes } from '../src/crypto/base64';
import { nobleEd25519Engine } from '../src/crypto/noble';
import {
  AmcpSession,
  type AuditCapability,
  AuditHost,
  Countersign,
  InProcessTransport,
  Level,
  Posture,
  type SealedRecord,
  SPEC_VERSION,
  transportFor,
  verifyLedger,
} from '../src/index';
import { Ed25519Signer, KeyRegistry, KeyRegistryVerifier, loadToolKey, type ToolKey } from '../src/l2';
import { McpAuditTransport } from '../src/mcp';
import { createAuditableMcpHandler } from '../src/mcp/http';
import { toNodeListener } from '../src/node';

const env = process.env;
const level = env.WALK_LEVEL === 'L2' ? Level.L2 : Level.L1;
const countersign = env.WALK_TOOL_COUNTERSIGN === 'host' ? Countersign.HOST : Countersign.NONE;
const posture = env.WALK_POSTURE === 'mandatory' ? Posture.MANDATORY : Posture.DEGRADED;
const operations = Number(env.WALK_OPERATIONS ?? '4');
// `high` serves the tool through `McpServer.registerTool` rather than a raw `tools/call` handler.
const highLevel = env.WALK_SERVER === 'high';
const discloseBytes = Number(env.WALK_DISCLOSE_BYTES ?? '0');
const dieAfter = Number(env.WALK_DIE_AFTER ?? '0');
const egressEvery = Number(env.WALK_EGRESS_EVERY ?? '0');
// The operations the tool performs but does not report as egress: §7.5's suppression by omission,
// which only a boundary observation can catch.
const unreportedEgress = Number(env.WALK_UNREPORTED_EGRESS ?? '0');

/** Rebuild the key the registry was provisioned with (§5.1), or mint one if the walk is Level 1. */
function onboardedKey(): ToolKey {
  const keyId = env.WALK_TOOL_KEY_ID ?? 'walk-tool-key';
  const secret = env.WALK_TOOL_PRIVATE_KEY;
  if (secret === undefined || secret === '') {
    const { publicKey, privateKey } = nobleEd25519Engine.generateKeyPair();
    return { keyId, publicKey, privateKey };
  }
  return loadToolKey(keyId, base64ToBytes(secret));
}

const capability: AuditCapability = { spec_version: SPEC_VERSION, level, attempt: 'request', countersign };
const toolKey = onboardedKey();

/**
 * A signer whose latency is uneven, the shape of every remote one (§5.1 KMS).
 *
 * Numbers first and waits after, which is the order the AWS KMS adapter works in: the number is
 * fixed before the latency that can reorder the emission.
 */
class RemoteSigner {
  #calls = 0;
  readonly #inner: Ed25519Signer;
  readonly keyId: string;
  constructor(inner: Ed25519Signer) {
    this.#inner = inner;
    this.keyId = inner.keyId;
  }
  async sign(event: Record<string, unknown>, signerSeq: number): Promise<Record<string, unknown>> {
    this.#calls += 1;
    // Captured before the await: reading the counter afterwards gives every caller the same value,
    // because awaiting the inner signer lets every other caller number first.
    const wait = Math.max(0, 60 - this.#calls * 6);
    const signed = await this.#inner.sign(event, signerSeq);
    // Each later call waits less than every earlier one, so without §7.4's section the emission
    // order is exactly the reverse of the numbering - deterministically, not by chance.
    await new Promise((resolve) => setTimeout(resolve, wait));
    return signed;
  }
}

const localSigner = level === Level.L2 ? Ed25519Signer.fromToolKey(toolKey) : undefined;
const signer =
  localSigner !== undefined && env.WALK_SIGNER === 'slow' ? new RemoteSigner(localSigner) : localSigner;

/** A store whose write yields, so the tool's own host has §7.1's window to get wrong. */
class YieldingStore {
  readonly rows: SealedRecord[] = [];
  async append(_partition: string, record: SealedRecord): Promise<void> {
    await Promise.resolve();
    this.rows.push(record);
  }
  async loadTail(): Promise<SealedRecord | null> {
    return null;
  }
  async readAll(): Promise<SealedRecord[]> {
    return [...this.rows];
  }
}

// The degraded posture records into a host the tool provides for itself (§6.2).
const localRegistry = new KeyRegistry();
localRegistry.registerToolKey(toolKey);
const localHost = new AuditHost(
  'tool-local',
  { ...capability, countersign: Countersign.NONE },
  {
    repository: new YieldingStore(),
    ...(level === Level.L2 ? { verifier: new KeyRegistryVerifier(localRegistry) } : {}),
  },
);

const HTTP_URL_LINE = 'WALK_HTTP_URL=';
const SHUTDOWN_BOUND_MS = 2_000;

/** Serve one `tools/call`, whichever server API dispatched it. */
async function readCustomers(audit: McpAuditTransport, requestId: string | number | undefined): Promise<CallToolResult> {
  const call = audit.call(requestId);
  const negotiation = call.negotiate(capability);
  const transport = transportFor(negotiation, {
    negotiated: call,
    fallback: new InProcessTransport(localHost),
    posture,
  });
  if (transport !== call) {
    // The degraded posture: the tool is its own host, and issues the session itself (§6.3).
    localHost.openSession(call.sessionId);
  }
  const session = new AmcpSession(transport, call.sessionId, signer === undefined ? {} : { signer });
  const disclose = discloseBytes > 0 ? { rows: 'x'.repeat(discloseBytes) } : undefined;
  let done = 0;

  try {
    await Promise.all(
      Array.from({ length: operations }, async (_unused, n) => {
        const egress = egressEvery > 0 && n % egressEvery === 0 && n >= unreportedEgress * egressEvery;
        await using action = await session.action(
          egress ? 'net.send' : 'db.read',
          { kind: egress ? 'endpoint' : 'table', ref: `customers_${n}` },
          { mutates: false, egress, ...(disclose ? { disclose } : {}) },
        );
        await Promise.resolve();
        done += 1;
        if (dieAfter > 0 && done >= dieAfter) {
          // The tool process dies with an attempt sealed and no outcome: the completeness gap §10.8
          // exists for, seen across a real process boundary.
          process.exit(1);
        }
        action.succeeded();
      }),
    );
  } finally {
    if (transport !== call) {
      await localHost.closeSession(call.sessionId);
    }
  }

  return {
    content: [
      {
        type: 'text',
        text:
          `negotiated=${negotiation.negotiated ? 'True' : 'False'} outcome=${negotiation.outcome} ` +
          `local_records=${localHost.records().length} ` +
          `local_verifies=${verifyLedger(localHost.records()).ok ? 'True' : 'False'} ` +
          `local_anomalies=${localHost.anomalies().length}`,
      },
    ],
  };
}

function buildServer(audit: McpAuditTransport): Server | McpServer {
  if (highLevel) {
    const server = new McpServer({ name: 'walk-tool', version: '0.0.0' });
    server.registerTool('read_customers', { description: 'read rows' }, (ctx) => readCustomers(audit, ctx.mcpReq.id));
    return server;
  }
  const server = new Server({ name: 'walk-tool', version: '0.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler('tools/list', async () => ({
    tools: [{ name: 'read_customers', description: 'read rows', inputSchema: { type: 'object' } }],
  }));
  server.setRequestHandler('tools/call', (_request, ctx) => readCustomers(audit, ctx.mcpReq.id));
  return server;
}

if (env.WALK_TRANSPORT === 'http') {
  const handler = createAuditableMcpHandler((audit) => buildServer(audit), { declares: capability });
  const server = createServer(toNodeListener(handler));
  server.listen(0, '127.0.0.1', () => {
    const address = server.address();
    if (address === null || typeof address === 'string') {
      process.exit(1);
    }
    process.stdout.write(`${HTTP_URL_LINE}http://127.0.0.1:${address.port}/mcp\n`);
  });
  let stopping = false;
  const stop = (): void => {
    if (stopping) {
      return;
    }
    stopping = true;
    // Held calls are cancelled and the listener closed; a connection that does not let go is not waited on.
    setTimeout(() => process.exit(0), SHUTDOWN_BOUND_MS).unref();
    server.closeAllConnections();
    void Promise.allSettled([handler.close(), new Promise((resolve) => server.close(resolve))]).then(() =>
      process.exit(0),
    );
  };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  // The runner holds this pipe open for the life of the case; its end means the runner has gone.
  process.stdin.once('end', stop);
  process.stdin.resume();
} else {
  const audit = new McpAuditTransport(new StdioServerTransport(), capability);
  // The official entry that picks the era from the opening message; `Server.connect` serves only the
  // `initialize` era.
  serveStdio(() => buildServer(audit), { transport: audit });
}
