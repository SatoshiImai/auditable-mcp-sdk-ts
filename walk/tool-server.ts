/**
 * An auditable MCP tool, served over real stdio, for the cross-language walk.
 *
 * The mirror of the Python SDK's `walk/tool_server.py`, so one host can drive either and compare
 * what lands in the ledger. That comparison is what §11.1 asks for: given identical inputs,
 * conformant implementations produce an identical `record_hash` across a language boundary.
 *
 * The knobs come from the environment, and the tool key is provisioned out-of-band (§5.1) by the
 * runner, so this process signs with the key the host's registry already holds.
 */

import { Server } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { ed25519 } from '@noble/curves/ed25519';
import {
  type AuditCapability,
  AuditHost,
  AmcpSession,
  InProcessTransport,
  Level,
  Posture,
  SPEC_VERSION,
  transportFor,
  type SealedRecord,
  verifyLedger,
  Witness,
} from '../src/index';
import { Ed25519Signer, KeyRegistry, KeyRegistryVerifier, type ToolKey } from '../src/l2';
import { McpAuditTransport, type McpTransport } from '../src/mcp';
import { base64ToBytes } from '../src/crypto/base64';
import { nobleEd25519Engine } from '../src/crypto/noble';

const env = process.env;
const level = env.WALK_LEVEL === 'L2' ? Level.L2 : Level.L1;
const witness = env.WALK_WITNESS === 'host' ? Witness.HOST : Witness.NONE;
const posture = env.WALK_POSTURE === 'mandatory' ? Posture.MANDATORY : Posture.DEGRADED;
const operations = Number(env.WALK_OPERATIONS ?? '4');
const discloseBytes = Number(env.WALK_DISCLOSE_BYTES ?? '0');
const dieAfter = Number(env.WALK_DIE_AFTER ?? '0');

/** Rebuild the key the registry was provisioned with (§5.1), or mint one if the walk is Level 1. */
function onboardedKey(): ToolKey {
  const keyId = env.WALK_TOOL_KEY_ID ?? 'walk-tool-key';
  const secret = env.WALK_TOOL_PRIVATE_KEY;
  if (secret === undefined || secret === '') {
    const { publicKey, privateKey } = nobleEd25519Engine.generateKeyPair();
    return { keyId, publicKey, privateKey };
  }
  const privateKey = base64ToBytes(secret);
  return { keyId, publicKey: ed25519.getPublicKey(privateKey), privateKey };
}

const capability: AuditCapability = { spec_version: SPEC_VERSION, level, attempt: 'request', witness };
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
  constructor(inner: Ed25519Signer) {
    this.#inner = inner;
  }
  async sign(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.#calls += 1;
    // Captured before the await: reading the counter afterwards gives every caller the same value,
    // because awaiting the inner signer lets every other caller number first.
    const wait = Math.max(0, 60 - this.#calls * 6);
    const signed = await this.#inner.sign(event);
    // Each later call waits less than every earlier one, so without §7.4's section the emission
    // order is exactly the reverse of the numbering - deterministically, not by chance.
    await new Promise((resolve) => setTimeout(resolve, wait));
    return signed;
  }
}

const startSignerSeq = Number(env.WALK_START_SIGNER_SEQ ?? '0');
const localSigner =
  level === Level.L2 ? Ed25519Signer.fromToolKey(toolKey, { startSignerSeq }) : undefined;
const signer =
  localSigner !== undefined && env.WALK_SIGNER === 'slow' ? new RemoteSigner(localSigner) : localSigner;

// The degraded posture records into a host the tool provides for itself (§6.2).
const localRegistry = new KeyRegistry();
localRegistry.registerToolKey(toolKey);
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

const localHost = new AuditHost(
  'tool-local',
  { spec_version: SPEC_VERSION, level, attempt: 'request', witness: Witness.NONE },
  {
    repository: new YieldingStore(),
    ...(level === Level.L2 ? { verifier: new KeyRegistryVerifier(localRegistry) } : {}),
  },
);

const audit = new McpAuditTransport(new StdioServerTransport() as unknown as McpTransport, capability);
const server = new Server({ name: 'walk-tool', version: '0.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler('tools/list', async () => ({
  tools: [{ name: 'read_customers', description: 'read rows', inputSchema: { type: 'object' } }],
}));

server.setRequestHandler('tools/call', async (request) => {
  const negotiation = audit.negotiate(capability);
  const transport = transportFor(negotiation, {
    negotiated: audit,
    fallback: new InProcessTransport(localHost),
    posture,
  });
  const callId = String((request.params?.arguments as Record<string, unknown> | undefined)?.call_id ?? 'call');
  const session = new AmcpSession(transport, callId, { signer });
  const disclose = discloseBytes > 0 ? { rows: 'x'.repeat(discloseBytes) } : undefined;
  let done = 0;

  await Promise.all(
    Array.from({ length: operations }, async (_unused, n) => {
      await using action = await session.action(
        'db.read',
        { kind: 'table', ref: `customers_${n}` },
        { mutates: false, egress: false, ...(disclose ? { disclose } : {}) },
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
});

await server.connect(audit as unknown as Parameters<Server['connect']>[0]);
