/**
 * Drive a tool over a real stdio pipe from a host built on this SDK, and check what the ledger holds.
 *
 * The Python SDK's `walk/run.py` is the other direction. Between them the two bindings are exercised
 * in both combinations - this host against that tool, and that host against this one - which is the
 * only way either `McpAuditReceiver` meets the other port's `McpAuditTransport` on a real wire.
 *
 * Each case states what it expects of the ledger, not of the SDK's internals, so a case that fails
 * names a fact about the audit trail.
 *
 *     npx tsx walk/run.ts             # every case
 *     npx tsx walk/run.ts crosslang   # the cases whose name contains `crosslang`
 */

import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { ed25519 } from '@noble/curves/ed25519';
import { AuditHost } from '../src/host';
import type { SealedRecord } from '../src/ledger';
import { type AuditCapability, Level, SPEC_VERSION, Witness } from '../src/models';
import { Ed25519WitnessSigner, KeyRegistry, KeyRegistryVerifier, KeyRole, type ToolKey } from '../src/l2';
import { capabilityOf, McpAuditReceiver, type McpTransport } from '../src/mcp';
import { RepositoryError } from '../src/storage/repository';
import { bytesToBase64 } from '../src/crypto/base64';
import { verifyLedger } from '../src/verify';

const HERE = dirname(fileURLToPath(import.meta.url));
const TS_TOOL = resolve(HERE, 'tool-server.ts');
const PY_REPO = resolve(HERE, '..', '..', 'auditable-mcp-sdk-python');
const PY_TOOL = resolve(PY_REPO, 'walk', 'tool_server.py');
const OPERATIONS = 4;

/** A durable repository whose write yields, which is where §7.1's window opens. */
class Store {
  readonly rows: SealedRecord[] = [];
  readonly #failAfter: number;

  constructor(failAfter = 0) {
    this.#failAfter = failAfter;
  }

  async append(_partition: string, record: SealedRecord): Promise<void> {
    await Promise.resolve();
    if (this.#failAfter > 0 && this.rows.length >= this.#failAfter) {
      throw new RepositoryError('the store went away');
    }
    this.rows.push(record);
  }

  async loadTail(): Promise<SealedRecord | null> {
    return null;
  }

  async readAll(): Promise<SealedRecord[]> {
    return [...this.rows];
  }
}

interface Case {
  name: string;
  tool: 'typescript' | 'python';
  environment: Record<string, string>;
  hostLevel?: Level;
  hostWitness?: Witness;
  audited?: boolean;
  expectNegotiated?: boolean;
  expectRecords?: number;
  expectLocalRecords?: number;
  calls?: number;
}

const CASES: Case[] = [
  { name: 'l1-negotiated', tool: 'typescript', environment: { WALK_LEVEL: 'L1' } },
  { name: 'l2-negotiated', tool: 'typescript', environment: { WALK_LEVEL: 'L2' }, hostLevel: Level.L2 },
  {
    name: 'l2-witnessed',
    tool: 'typescript',
    environment: { WALK_LEVEL: 'L2', WALK_WITNESS: 'host' },
    hostLevel: Level.L2,
    hostWitness: Witness.HOST,
  },
  {
    name: 'l2-with-a-remote-signer',
    tool: 'typescript',
    environment: { WALK_LEVEL: 'L2', WALK_SIGNER: 'slow', WALK_OPERATIONS: '8' },
    hostLevel: Level.L2,
    expectRecords: 16,
  },
  {
    name: 'degraded-host-does-not-speak-it',
    tool: 'typescript',
    environment: { WALK_LEVEL: 'L2' },
    audited: false,
    expectNegotiated: false,
    expectRecords: 0,
    expectLocalRecords: OPERATIONS * 2,
  },
  { name: 'crosslang-python-tool-l1', tool: 'python', environment: { WALK_LEVEL: 'L1' } },
  {
    name: 'crosslang-python-tool-l2',
    tool: 'python',
    environment: { WALK_LEVEL: 'L2' },
    hostLevel: Level.L2,
  },
  {
    name: 'crosslang-python-tool-l2-witnessed',
    tool: 'python',
    environment: { WALK_LEVEL: 'L2', WALK_WITNESS: 'host' },
    hostLevel: Level.L2,
    hostWitness: Witness.HOST,
  },
  {
    name: 'crosslang-python-tool-remote-signer',
    tool: 'python',
    environment: { WALK_LEVEL: 'L2', WALK_SIGNER: 'slow', WALK_OPERATIONS: '8' },
    hostLevel: Level.L2,
    expectRecords: 16,
  },
  {
    name: 'crosslang-python-tool-degraded-concurrency',
    tool: 'python',
    environment: { WALK_LEVEL: 'L1', WALK_OPERATIONS: '16' },
    audited: false,
    expectNegotiated: false,
    expectRecords: 0,
    expectLocalRecords: 32,
  },
];

/** Mint the tool's key here and hand out each half, the way onboarding does (§5.1). */
function onboard(): { key: ToolKey; secret: string } {
  const privateKey = ed25519.utils.randomSecretKey();
  const key: ToolKey = { keyId: 'walk-tool-key', publicKey: ed25519.getPublicKey(privateKey), privateKey };
  return { key, secret: bytesToBase64(privateKey) };
}

async function runCase(testCase: Case): Promise<string[]> {
  const findings: string[] = [];
  const audited = testCase.audited ?? true;
  const expectNegotiated = testCase.expectNegotiated ?? true;
  const expectRecords = testCase.expectRecords ?? OPERATIONS * 2;
  const expectLocalRecords = testCase.expectLocalRecords ?? 0;
  const { key, secret } = onboard();

  const store = new Store();
  const registry = new KeyRegistry(KeyRole.TOOL);
  registry.registerToolKey(key);
  const witnessSecret = ed25519.utils.randomSecretKey();
  const capability: AuditCapability = {
    spec_version: SPEC_VERSION,
    level: testCase.hostLevel ?? Level.L1,
    attempt: 'request',
    witness: testCase.hostWitness ?? Witness.NONE,
  };
  const host = new AuditHost('tenant-walk', capability, {
    repository: store,
    ...(capability.level === Level.L2 ? { verifier: new KeyRegistryVerifier(registry) } : {}),
    ...(capability.witness === Witness.HOST
      ? { witnessSigner: new Ed25519WitnessSigner('walk-host-key', witnessSecret) }
      : {}),
  });

  const isPython = testCase.tool === 'python';
  const wire = new StdioClientTransport({
    command: isPython ? (process.env.WALK_PYTHON ?? 'python') : 'npx',
    args: isPython ? [PY_TOOL] : ['tsx', TS_TOOL],
    env: {
      ...(process.env as Record<string, string>),
      WALK_OPERATIONS: String(OPERATIONS),
      WALK_TOOL_KEY_ID: key.keyId,
      WALK_TOOL_PRIVATE_KEY: secret,
      ...testCase.environment,
    },
    // The other port pins its interpreter with a local .python-version, which only resolves from
    // inside its own tree; spawning from here would pick whatever the shim's global happens to be.
    ...(isPython ? { cwd: PY_REPO } : {}),
    stderr: 'ignore',
  });

  const receiver = audited ? new McpAuditReceiver(wire as unknown as McpTransport, host) : undefined;
  const client = new Client({ name: 'walk-host', version: '0.0.0' });
  await client.connect((receiver ?? wire) as unknown as Parameters<Client['connect']>[0]);

  try {
    const declared = capabilityOf(client.getServerCapabilities());
    if (declared === undefined) {
      findings.push('the tool declared nothing at initialize (§6.1)');
    }
    const tools = await client.listTools();
    if (tools.tools.map((tool) => tool.name).join(',') !== 'read_customers') {
      findings.push('ordinary MCP changed because this extension is present (§6.2)');
    }
    const results = await Promise.all(
      Array.from({ length: testCase.calls ?? 1 }, (_u, n) =>
        client.callTool({ name: 'read_customers', arguments: { call_id: `walk-call-${n}` } }),
      ),
    );
    for (const result of results) {
      const text = (result.content as { text?: string }[]).map((block) => block.text ?? '').join('');
      if (result.isError) {
        findings.push(`the tool call failed: ${text}`);
        continue;
      }
      if (!text.includes(`negotiated=${expectNegotiated ? 'True' : 'False'}`)) {
        findings.push(`negotiation was not ${expectNegotiated}: ${text}`);
      }
      if (!text.includes(`local_records=${expectLocalRecords}`)) {
        findings.push(`the tool-local ledger is not ${expectLocalRecords}: ${text}`);
      }
      if (expectLocalRecords > 0 && !text.includes('local_verifies=True')) {
        findings.push(`the tool's own ledger does not verify: ${text}`);
      }
      if (expectLocalRecords > 0 && !text.includes('local_anomalies=0')) {
        findings.push(`the tool's own ledger holds anomalies: ${text}`);
      }
    }
    await client.ping();
  } finally {
    await client.close();
  }

  const records = host.records();
  if (records.length !== expectRecords) {
    findings.push(`ledger holds ${records.length} records, expected ${expectRecords}`);
  }
  if (records.length > 0) {
    const report = verifyLedger(records, host.digest());
    if (!report.ok) {
      findings.push(`ledger does not verify: ${report.issues.map((issue) => issue.kind).join(',')}`);
    }
    if (host.anomalies().length > 0) {
      findings.push(
        `anomalies against a tool that did nothing wrong: ${host.anomalies().map((a) => a.kind).join(',')}`,
      );
    }
    const seqs = records.map((record) => record.seq);
    if (new Set(seqs).size !== seqs.length) {
      findings.push(`two records share a position (§7.1): ${seqs.join(',')}`);
    }
    if (capability.witness === Witness.HOST && records.some((r) => r.host_signature === undefined)) {
      findings.push('a witnessing host left a record unsigned (§7.1)');
    }
    if (store.rows.map((r) => r.record_hash).join(',') !== records.map((r) => r.record_hash).join(',')) {
      findings.push('the durable store and the in-memory chain disagree');
    }
  }
  return findings;
}

const selectors = process.argv.slice(2);
const chosen = CASES.filter((c) => selectors.length === 0 || selectors.some((s) => c.name.includes(s)));
const runnable = chosen.filter((c) => c.tool !== 'python' || existsSync(PY_TOOL));
if (runnable.length !== chosen.length) {
  console.log(`skipping the cross-language cases: ${PY_TOOL} is not checked out`);
}

let failures = 0;
for (const testCase of runnable) {
  let findings: string[];
  try {
    findings = await runCase(testCase);
  } catch (error) {
    findings = [`the case raised: ${String(error).slice(0, 180)}`];
  }
  console.log(`[${findings.length === 0 ? '  ok  ' : 'FINDING'}] ${testCase.name}`);
  for (const finding of findings) {
    console.log(`          - ${finding}`);
    failures += 1;
  }
}
console.log(`\n${runnable.length} cases, ${failures} findings`);
process.exit(failures > 0 ? 1 : 0);
