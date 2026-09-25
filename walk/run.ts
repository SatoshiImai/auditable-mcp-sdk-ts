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
 *
 * `WALK_TRANSPORT=http` runs the MCP 2026-07-28 cases over Streamable HTTP instead of stdio: the tool is
 * started with the same variable, serves through the SDK's HTTP entry, and reports where with one stdout
 * line `WALK_HTTP_URL=<url>`; the host connects with the official `StreamableHTTPClientTransport`. The
 * `initialize` cases stay on stdio (§6.5 over HTTP is not served). The Python tool is driven over HTTP by
 * the same contract.
 *
 * The cross-language cases use the Python checkout beside this one - `auditable-mcp-sdk-python`, or for a
 * worktree `auditable-mcp-sdk-ts-<suffix>` the one named `auditable-mcp-sdk-python-<suffix>` - or the one
 * `WALK_PY_REPO` names, and run it with the interpreter that imports that checkout's own `auditable_mcp`:
 * `WALK_PYTHON` if set, else the checkout's `.venv`, else a pyenv environment named after its
 * `.python-version`. An interpreter that imports another checkout is never used, so a worktree never runs
 * another checkout's code.
 */

import { type ChildProcess, spawn, spawnSync } from 'node:child_process';

import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { ed25519 } from '@noble/curves/ed25519';
import { AuditHost } from '../src/host';
import type { SealedRecord } from '../src/ledger';
import { type AuditCapability, Level, SPEC_VERSION, Countersign } from '../src/models';
import {
  Ed25519Countersigner,
  generateToolKey,
  KeyRegistry,
  KeyRegistryVerifier,
  KeyRole,
  type ToolKey,
  toolKeyPkcs8,
} from '../src/l2';
import { capabilityOf, McpAuditReceiver } from '../src/mcp';
import { RepositoryError } from '../src/storage/repository';
import { bytesToBase64 } from '../src/crypto/base64';
import { verifyLedger } from '../src/verify';

const HERE = dirname(fileURLToPath(import.meta.url));
const TS_TOOL = resolve(HERE, 'tool-server.ts');
const TS_REPO_NAME = 'auditable-mcp-sdk-ts';
const PY_REPO_NAME = 'auditable-mcp-sdk-python';
const PY_IMPORT_PROBE = 'import auditable_mcp, sys; sys.stdout.write(auditable_mcp.__file__)';

/** The Python checkout this one pairs with: the worktree of the same suffix, when there is one. */
function pythonRepo(): string {
  if (process.env.WALK_PY_REPO !== undefined) {
    return resolve(process.env.WALK_PY_REPO);
  }
  const parent = resolve(HERE, '..', '..');
  const own = basename(resolve(HERE, '..'));
  const paired = own.startsWith(TS_REPO_NAME) ? resolve(parent, PY_REPO_NAME + own.slice(TS_REPO_NAME.length)) : undefined;
  return paired !== undefined && existsSync(paired) ? paired : resolve(parent, PY_REPO_NAME);
}

/** Whether `python` imports `auditable_mcp` from inside `repo`. */
function importsFrom(python: string, repo: string): boolean {
  const probe = spawnSync(python, ['-c', PY_IMPORT_PROBE], { cwd: repo, encoding: 'utf8', timeout: 20_000 });
  if (probe.status !== 0 || typeof probe.stdout !== 'string' || probe.stdout === '') {
    return false;
  }
  return realpathSync(probe.stdout).startsWith(realpathSync(repo) + sep);
}

/** The interpreter that runs `repo`'s own code, or undefined when none is found. */
function pythonFor(repo: string): string | undefined {
  const candidates: string[] = [];
  if (process.env.WALK_PYTHON !== undefined) {
    candidates.push(process.env.WALK_PYTHON);
  }
  candidates.push(join(repo, '.venv', 'bin', 'python'));
  const versionFile = join(repo, '.python-version');
  const pyenvVersions = join(process.env.PYENV_ROOT ?? join(homedir(), '.pyenv'), 'versions');
  if (existsSync(versionFile) && existsSync(pyenvVersions)) {
    const named = readFileSync(versionFile, 'utf8').trim();
    for (const version of readdirSync(pyenvVersions).sort()) {
      if (version.startsWith(named)) {
        candidates.push(join(pyenvVersions, version, 'bin', 'python'));
      }
    }
  }
  return candidates.find((python) => (python.includes(sep) ? existsSync(python) : true) && importsFrom(python, repo));
}

const PY_REPO = pythonRepo();
const PY_TOOL = resolve(PY_REPO, 'walk', 'tool_server.py');
const PY_PYTHON = existsSync(PY_TOOL) ? pythonFor(PY_REPO) : undefined;
const OPERATIONS = 4;
const OVER_HTTP = process.env.WALK_TRANSPORT === 'http';
const HTTP_URL_LINE = 'WALK_HTTP_URL=';
const HTTP_START_TIMEOUT_MS = 30_000;
/** How long a tool's processes may take to exit once its case has closed it. */
const TOOL_EXIT_BOUND_MS = 5_000;
const TOOL_EXIT_POLL_MS = 100;

/** Every process under `root`, `root` included, as `ps` sees them now. */
function processTree(root: number): number[] {
  const listed = spawnSync('ps', ['-eo', 'pid=,ppid='], { encoding: 'utf8' });
  const children = new Map<number, number[]>();
  for (const line of (listed.stdout ?? '').split('\n')) {
    const [pid, ppid] = line.trim().split(/\s+/).map(Number);
    if (pid !== undefined && ppid !== undefined && Number.isInteger(pid) && Number.isInteger(ppid)) {
      children.set(ppid, [...(children.get(ppid) ?? []), pid]);
    }
  }
  const tree = [root];
  for (let index = 0; index < tree.length; index += 1) {
    tree.push(...(children.get(tree[index] ?? -1) ?? []));
  }
  return tree;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error instanceof Error && 'code' in error && error.code === 'EPERM';
  }
}

/**
 * Wait for the processes of a closed tool to exit, and report those still running after the bound; they
 * are then killed so the next case starts clean. A wrapper (`npx`, `tsx`) that exits leaves its children
 * to init, so the tree is taken before the tool is closed.
 */
async function outlivers(tree: number[]): Promise<number[]> {
  const deadline = Date.now() + TOOL_EXIT_BOUND_MS;
  let alive = tree.filter(isAlive);
  while (alive.length > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, TOOL_EXIT_POLL_MS));
    alive = alive.filter(isAlive);
  }
  for (const pid of alive) {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      // Exited between the check and the kill.
    }
  }
  return alive;
}

/** Start a tool that serves over HTTP, and wait for the line that says where. */
function startHttpTool(
  command: string,
  args: string[],
  environment: Record<string, string>,
  cwd: string | undefined,
): Promise<{ url: URL; child: ChildProcess }> {
  // Its own process group, so that stopping it reaches whatever a wrapper (`npx`, `tsx`) started; its stdin
  // is a pipe from this process, whose end tells the tool to stop if this process dies without stopping it.
  const child = spawn(command, args, {
    env: { ...environment, WALK_TRANSPORT: 'http' },
    ...(cwd === undefined ? {} : { cwd }),
    stdio: ['pipe', 'pipe', 'ignore'],
    detached: true,
  });
  return new Promise((resolve, reject) => {
    let buffered = '';
    const timer = setTimeout(() => {
      stopGroup(child);
      reject(new Error(`the tool did not write ${HTTP_URL_LINE} within ${HTTP_START_TIMEOUT_MS}ms`));
    }, HTTP_START_TIMEOUT_MS);
    child.stdout?.on('data', (chunk: Buffer) => {
      buffered += chunk.toString('utf8');
      const line = buffered.split('\n').find((candidate) => candidate.startsWith(HTTP_URL_LINE));
      if (line !== undefined) {
        clearTimeout(timer);
        resolve({ url: new URL(line.slice(HTTP_URL_LINE.length).trim()), child });
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`the tool exited (${String(code)}) before writing ${HTTP_URL_LINE}`));
    });
  });
}

/** Stop a tool started by {@link startHttpTool}: its whole process group, as a terminal would. */
function stopGroup(child: ChildProcess): void {
  child.stdin?.end();
  if (child.pid !== undefined) {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch {
      // The group has already exited.
    }
  }
}

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
  hostCountersign?: Countersign;
  audited?: boolean;
  expectNegotiated?: boolean;
  expectRecords?: number;
  expectLocalRecords?: number;
  calls?: number;
  /** MCP 2026-07-28 and §6.4, or the `initialize` handshake and §6.5. */
  modern?: boolean;
}

const CASES: Case[] = [
  { name: 'l1-negotiated', tool: 'typescript', environment: { WALK_LEVEL: 'L1' } },
  { name: 'l2-negotiated', tool: 'typescript', environment: { WALK_LEVEL: 'L2' }, hostLevel: Level.L2 },
  {
    name: 'l2-mcpserver-register-tool',
    tool: 'typescript',
    environment: { WALK_LEVEL: 'L2', WALK_SERVER: 'high' },
    hostLevel: Level.L2,
  },
  {
    name: 'l2-countersigned',
    tool: 'typescript',
    environment: { WALK_LEVEL: 'L2' },
    hostLevel: Level.L2,
    hostCountersign: Countersign.HOST,
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
    name: 'crosslang-python-tool-l2-countersigned',
    tool: 'python',
    environment: { WALK_LEVEL: 'L2' },
    hostLevel: Level.L2,
    hostCountersign: Countersign.HOST,
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
  {
    name: 'crosslang-python-tool-two-concurrent-calls',
    tool: 'python',
    environment: { WALK_LEVEL: 'L2' },
    hostLevel: Level.L2,
    calls: 2,
    expectRecords: OPERATIONS * 2 * 2,
  },
];

// The same cases under the `initialize` handshake (§6.5): two ports have to agree on both bindings.
CASES.push(...CASES.map((testCase) => ({ ...testCase, name: `${testCase.name}-initialize`, modern: false })));

/**
 * Mint the tool's key here and hand out each half, the way onboarding does (§5.1).
 *
 * The private half travels as PKCS#8, the form the SDK pins, so the Python tool reads exactly what
 * this one writes.
 */
function onboard(): { key: ToolKey; secret: string } {
  const key = generateToolKey('walk-tool-key');
  return { key, secret: bytesToBase64(toolKeyPkcs8(key)) };
}

/**
 * Report any break in the `signer_seq` the host sealed, per key and session (§7.4).
 *
 * Each session's sequence has to be 0, 1, 2, ... with no repeat and no hole: a repeat means two
 * writers numbered over each other, and a hole means a number was taken and never emitted.
 */
function signerSeqGaps(records: SealedRecord[]): string[] {
  const bySession = new Map<string, number[]>();
  for (const { event } of records) {
    if (typeof event.key_id === 'string' && typeof event.session_id === 'string' && typeof event.signer_seq === 'number') {
      const key = `${event.key_id} in ${event.session_id}`;
      bySession.set(key, [...(bySession.get(key) ?? []), event.signer_seq]);
    }
  }
  const findings: string[] = [];
  for (const [key, seen] of bySession) {
    const sorted = [...seen].sort((a, b) => a - b);
    if (sorted.some((value, index) => value !== index)) {
      findings.push(`signer_seq for ${key} is ${sorted.join(',')}, not 0..n (§7.4)`);
    }
  }
  return findings;
}

async function runCase(testCase: Case): Promise<string[]> {
  const findings: string[] = [];
  const audited = testCase.audited ?? true;
  const expectNegotiated = testCase.expectNegotiated ?? true;
  const expectRecords = testCase.expectRecords ?? OPERATIONS * 2;
  const expectLocalRecords = testCase.expectLocalRecords ?? 0;
  const modern = testCase.modern ?? true;
  const { key, secret } = onboard();

  const store = new Store();
  const registry = new KeyRegistry(KeyRole.TOOL);
  registry.registerToolKey(key);
  const countersignSecret = ed25519.utils.randomSecretKey();
  const capability: AuditCapability = {
    spec_version: SPEC_VERSION,
    level: testCase.hostLevel ?? Level.L1,
    attempt: 'request',
    countersign: testCase.hostCountersign ?? Countersign.NONE,
  };
  const host = new AuditHost('tenant-walk', capability, {
    repository: store,
    ...(capability.level === Level.L2 ? { verifier: new KeyRegistryVerifier(registry) } : {}),
    ...(capability.countersign === Countersign.HOST
      ? { countersigner: new Ed25519Countersigner('walk-host-key', countersignSecret) }
      : {}),
  });

  const isPython = testCase.tool === 'python';
  const command = isPython ? (PY_PYTHON ?? 'python') : 'npx';
  const args = isPython ? [PY_TOOL] : ['tsx', TS_TOOL];
  const environment = {
    ...(process.env as Record<string, string>),
    WALK_OPERATIONS: String(OPERATIONS),
    WALK_TOOL_KEY_ID: key.keyId,
    WALK_TOOL_PRIVATE_KEY: secret,
    ...testCase.environment,
  };
  // The other port pins its interpreter with a local .python-version, which only resolves from
  // inside its own tree; spawning from here would pick whatever the shim's global happens to be.
  const cwd = isPython ? PY_REPO : undefined;
  const httpTool = OVER_HTTP && modern ? await startHttpTool(command, args, environment, cwd) : undefined;
  const wire =
    httpTool === undefined
      ? new StdioClientTransport({
          command,
          args,
          env: { ...environment, WALK_TRANSPORT: 'stdio' },
          ...(cwd === undefined ? {} : { cwd }),
          stderr: 'ignore',
        })
      : new StreamableHTTPClientTransport(httpTool.url);

  const receiver = audited ? new McpAuditReceiver(wire, host) : undefined;
  const client = new Client(
    { name: 'walk-host', version: '0.0.0' },
    modern ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {},
  );
  await client.connect(receiver ?? wire);

  try {
    const declared = capabilityOf(client.getServerCapabilities());
    if (declared === undefined) {
      findings.push('the tool declared nothing in the handshake (§6.1)');
    }
    const tools = await client.listTools();
    if (tools.tools.map((tool) => tool.name).join(',') !== 'read_customers') {
      findings.push('ordinary MCP changed because this extension is present (§6.2)');
    }
    const results = await Promise.all(
      Array.from({ length: testCase.calls ?? 1 }, (_u, n) =>
        client.callTool({ name: 'read_customers', arguments: {} }),
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
    if (!modern) {
      // MCP 2026-07-28 has no `ping`; under the handshake it proves the connection outlived the calls.
      await client.ping();
    }
  } finally {
    const root = httpTool?.child.pid ?? (wire instanceof StdioClientTransport ? wire.pid : null) ?? undefined;
    const tree = root === undefined ? [] : processTree(root);
    await client.close();
    if (httpTool !== undefined) {
      stopGroup(httpTool.child);
    }
    const left = await outlivers(tree);
    if (left.length > 0) {
      findings.push(`${left.length} tool process(es) outlived the case by ${TOOL_EXIT_BOUND_MS}ms: ${left.join(',')}`);
    }
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
    if (capability.countersign === Countersign.HOST && records.some((r) => r.host_signature === undefined)) {
      findings.push('a countersigning host left a record unsigned (§7.1)');
    }
    if (store.rows.map((r) => r.record_hash).join(',') !== records.map((r) => r.record_hash).join(',')) {
      findings.push('the durable store and the in-memory chain disagree');
    }
    findings.push(...signerSeqGaps(records));
  }
  return findings;
}

const selectors = process.argv.slice(2);
const chosen = CASES.filter((c) => selectors.length === 0 || selectors.some((s) => c.name.includes(s)));
const runnable = chosen.filter((c) => c.tool !== 'python' || PY_PYTHON !== undefined);
if (runnable.length !== chosen.length) {
  console.log(
    existsSync(PY_TOOL)
      ? `skipping the cross-language cases: no interpreter imports auditable_mcp from ${PY_REPO}`
      : `skipping the cross-language cases: ${PY_TOOL} is not checked out`,
  );
} else if (chosen.some((c) => c.tool === 'python')) {
  console.log(`cross-language cases: ${PY_REPO} with ${PY_PYTHON}`);
}

let failures = 0;
for (const testCase of runnable) {
  let findings: string[];
  try {
    findings = await runCase(testCase);
  } catch (error) {
    findings = [`the case raised: ${String(error).slice(0, 180)}`];
  }
  const over = OVER_HTTP && testCase.modern !== false ? 'http' : 'stdio';
  console.log(`[${findings.length === 0 ? '  ok  ' : 'FINDING'}] ${testCase.name} (${over})`);
  for (const finding of findings) {
    console.log(`          - ${finding}`);
    failures += 1;
  }
}
console.log(`\n${runnable.length} cases, ${failures} findings`);
process.exit(failures > 0 ? 1 : 0);
