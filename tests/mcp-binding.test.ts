/** The MCP bindings: the §6 exchange on a real MCP connection, under §6.5 and under §6.4. */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, Server } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { describe, expect, it, vi } from 'vitest';
import { transportFor } from '../src/degradation';
import { AuditHost, type AuditHostOptions } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  CountersignatureRegistryVerifier,
  Ed25519Countersigner,
  Ed25519Signer,
  generateToolKey,
  KeyRegistry,
  KeyRegistryVerifier,
  KeyRole,
  SignatureAlgorithm,
} from '../src/l2';
import {
  ATTEMPT_METHOD,
  auditExtension,
  capabilityOf,
  declare,
  declareInto,
  INITIALIZE_METHOD,
  type JsonRpcFrame,
  MAX_IDLE_SESSIONS,
  MAX_ROUNDS_PER_CALL,
  McpAuditReceiver,
  McpAuditTransport,
  McpBindingError,
  type McpTransport,
  OUTCOME_METHOD,
  ROUND_TOKEN_PREFIX,
  UnknownCallError,
  UnnegotiatedSendError,
} from '../src/mcp';
import {
  type AttemptResponse,
  type AuditCapability,
  Countersign,
  EXTENSION_ID,
  Level,
  SPEC_VERSION,
} from '../src/models';
import { AmcpAbortedError, AmcpSession, type EventSigner, type SessionNumbering } from '../src/session';
import { type AuditEndpoint, unavailable } from '../src/transport';
import { verifyLedger } from '../src/verify';
import { MonotonicClock, SESSION } from './helpers';

const TOOL_CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};
const CALL_TIMEOUT_MS = 5_000;
const MODERN_VERSION = '2026-07-28';

const ACCEPT = {
  status: 'accept',
  seq: 0,
  record_hash: 'a'.repeat(64),
  host_ts: '2026-07-15T00:00:01.000Z',
  previous_hash: '0'.repeat(64),
};

function auditHost(capability: AuditCapability = TOOL_CAPABILITY, options: AuditHostOptions = {}): AuditHost {
  return new AuditHost('tenant-a', capability, { clock: new MonotonicClock(), ...options });
}

function l2(countersign: Countersign = Countersign.NONE): AuditCapability {
  return { spec_version: SPEC_VERSION, level: Level.L2, attempt: 'request', countersign };
}

/** Accepts any signature: the tool's own fallback host is not what these tests are about. */
const ANY_KEY = {
  async verify(): Promise<null> {
    return null;
  },
};

/** How the tool under test serves `tools/call`, and what it saw. */
class Tool {
  readonly fallback: AuditHost;
  performed = 0;
  readonly negotiated: boolean[] = [];
  readonly sessions: string[] = [];
  /** What the handler saw when it tried to send on a call that was not negotiated (§6.2). */
  readonly refused: string[] = [];

  constructor(
    readonly declares: AuditCapability = TOOL_CAPABILITY,
    readonly options: {
      operations?: number;
      signer?: EventSigner;
      countersignatureRegistry?: KeyRegistry;
      negotiateWith?: AuditCapability;
      seen?: string[];
      /** Operation n starts n × this many milliseconds after the call does. */
      staggerMs?: number;
      /** The handler throws once its operations settle, so the call ends in a JSON-RPC error. */
      throwAfter?: boolean;
    } = {},
  ) {
    const own = { ...declares, countersign: Countersign.NONE };
    this.fallback = auditHost(own, declares.level === Level.L1 ? {} : { verifier: ANY_KEY });
  }

  get operations(): number {
    return this.options.operations ?? 1;
  }
}

/**
 * Serve the tool on `transport` the way the official SDK serves both eras: the opening message picks the
 * era, and one server from the factory is pinned for the connection.
 */
function serveTool(transport: McpAuditTransport, tool: Tool): { close: () => Promise<void> } {
  return serveStdio(() => buildServer(transport, tool), { transport });
}

/** A tool server whose one tool records the operations it performs, however the call negotiated. */
function buildServer(transport: McpAuditTransport, tool: Tool): Server {
  const server = new Server({ name: 'audited-tool', version: '0.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler('tools/list', async () => ({
    tools: [{ name: 'read_customers', description: 'read', inputSchema: { type: 'object' } }],
  }));
  server.setRequestHandler('tools/call', async (_request, ctx) => {
    const call = transport.call(ctx.mcpReq.id);
    if (tool.options.negotiateWith !== undefined) {
      try {
        call.negotiate(tool.options.negotiateWith);
      } catch (error) {
        tool.options.seen?.push(error instanceof McpBindingError ? 'McpBindingError' : String(error));
      }
    }
    const negotiation = call.negotiate(tool.declares);
    tool.negotiated.push(negotiation.negotiated);
    tool.sessions.push(call.sessionId);
    if (!negotiation.negotiated) {
      for (const send of [() => call.sendAttempt({}), () => call.sendOutcome({})]) {
        try {
          await send();
        } catch (error) {
          if (error instanceof UnnegotiatedSendError) {
            tool.refused.push('UnnegotiatedSendError');
          }
        }
      }
    }
    const registry = tool.options.countersignatureRegistry;
    const chosen = transportFor(negotiation, { negotiated: call, fallback: new InProcessTransport(tool.fallback) });
    if (chosen !== call) {
      tool.fallback.openSession(call.sessionId);
    }
    const session = new AmcpSession(chosen, call.sessionId, {
      ...(tool.options.signer === undefined ? {} : { signer: tool.options.signer }),
      ...(registry === undefined ? {} : { countersignatureVerifier: new CountersignatureRegistryVerifier(registry) }),
      requireCountersign: tool.declares.countersign === Countersign.HOST,
    });
    const operation = async (n: number): Promise<void> => {
      if (tool.options.staggerMs !== undefined) {
        await new Promise((resolve) => setTimeout(resolve, n * (tool.options.staggerMs as number)));
      }
      await using action = await session.action(
        'db.read',
        { kind: 'table', ref: `customers_${n}` },
        { mutates: false, egress: false },
      );
      tool.performed += 1;
      action.succeeded();
    };
    let aborted: string[] = [];
    try {
      const settled = await Promise.allSettled(Array.from({ length: tool.operations }, (_, n) => operation(n)));
      const reasons = settled.flatMap((outcome) =>
        outcome.status === 'rejected' && outcome.reason instanceof AmcpAbortedError ? [outcome.reason.reason] : [],
      );
      aborted = [...new Set(reasons)].sort();
      const other = settled.find(
        (outcome) => outcome.status === 'rejected' && !(outcome.reason instanceof AmcpAbortedError),
      );
      if (other !== undefined && other.status === 'rejected') {
        throw other.reason;
      }
    } finally {
      if (chosen !== call) {
        await tool.fallback.closeSession(call.sessionId);
      }
    }
    if (tool.options.throwAfter === true) {
      throw new Error(`the handler failed after ${tool.performed} operations`);
    }
    if (aborted.length > 0) {
      return { content: [{ type: 'text', text: `aborted: ${aborted.join(',')}` }], isError: true };
    }
    return { content: [{ type: 'text', text: `read ${tool.operations} rows` }] };
  });
  return server;
}

interface Connection {
  client: Client;
  transport: McpAuditTransport;
  close: () => Promise<void>;
}

/** A live MCP session, under 2026-07-28 (`modern`) or `initialize`, audited when `endpoint` is given. */
async function connection(
  endpoint: AuditEndpoint | undefined,
  tool: Tool,
  options: { modern: boolean; requestTimeoutMs?: number },
): Promise<Connection> {
  const [clientWire, serverWire] = InMemoryTransport.createLinkedPair();
  const transport = new McpAuditTransport(serverWire, tool.declares, {
    requestTimeoutMs: options.requestTimeoutMs ?? CALL_TIMEOUT_MS,
  });
  const server = serveTool(transport, tool);
  const client = new Client(
    { name: 'host', version: '0.0.0' },
    options.modern ? { versionNegotiation: { mode: { pin: MODERN_VERSION } } } : {},
  );
  const clientTransport =
    endpoint === undefined
      ? clientWire
      : new McpAuditReceiver(clientWire, endpoint, { requestTimeoutMs: options.requestTimeoutMs ?? CALL_TIMEOUT_MS });
  await client.connect(clientTransport);
  return {
    client,
    transport,
    close: async () => {
      await Promise.all([client.close(), server.close()]);
    },
  };
}

type CallResult = Awaited<ReturnType<Client['callTool']>>;

async function callTool(live: Connection): Promise<CallResult> {
  return live.client.callTool({ name: 'read_customers', arguments: {} }, { timeout: CALL_TIMEOUT_MS });
}

/** Connect, call the tool `calls` times, and close. */
async function run(
  endpoint: AuditEndpoint | undefined,
  tool: Tool,
  options: { modern: boolean; requestTimeoutMs?: number; calls?: number },
): Promise<CallResult[]> {
  const live = await connection(endpoint, tool, options);
  const results: CallResult[] = [];
  try {
    for (let i = 0; i < (options.calls ?? 1); i += 1) {
      results.push(await callTool(live));
    }
  } finally {
    await live.close();
  }
  return results;
}

/** Let the seams run until `predicate` holds, failing rather than hanging if it never does. */
async function until(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + CALL_TIMEOUT_MS;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('the condition never held');
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function textOf(result: CallResult): string {
  const [first] = result.content as { type: string; text?: string }[];
  return first?.text ?? '';
}

const BINDINGS: [string, boolean][] = [
  ['§6.4 MRTR', true],
  ['§6.5 initialize', false],
];

describe('declaration (§6.1)', () => {
  it('keeps the extensions a party already had', () => {
    const declared = declare({ tools: {}, extensions: { 'org.example/other': {} } }, TOOL_CAPABILITY);
    expect(Object.keys(declared.extensions ?? {})).toEqual(['org.example/other', EXTENSION_ID]);
    expect(capabilityOf(declared)).toEqual(TOOL_CAPABILITY);
  });

  it('does not change the capabilities it was given', () => {
    const capabilities = { tools: {} };
    declare(capabilities, TOOL_CAPABILITY);
    expect(capabilityOf(capabilities)).toBeUndefined();
  });

  it('carries the capability object itself, not a wrapper around it', () => {
    expect(auditExtension(TOOL_CAPABILITY)).toEqual({ [EXTENSION_ID]: TOOL_CAPABILITY });
  });

  it('reads a peer that declared nothing as no declaration', () => {
    expect(capabilityOf({})).toBeUndefined();
    expect(capabilityOf(undefined)).toBeUndefined();
    expect(capabilityOf({ extensions: {} })).toBeUndefined();
  });

  it('reads a declaration that does not validate as no declaration', () => {
    expect(capabilityOf({ extensions: { [EXTENSION_ID]: { level: 'L1' } } })).toBeUndefined();
    expect(capabilityOf({ extensions: { [EXTENSION_ID]: 'L1' } })).toBeUndefined();
  });

  it('declareInto writes through a wire mapping', () => {
    const capabilities: Record<string, unknown> = { roots: {} };
    declareInto(capabilities, TOOL_CAPABILITY);
    expect(capabilityOf(capabilities)).toEqual(TOOL_CAPABILITY);
    expect(capabilities.roots).toEqual({});
  });
});

describe.each(BINDINGS)('both bindings: %s', (_name, modern) => {
  it('an audited call seals its attempt and outcome under the host’s session (§6.3)', async () => {
    const host = auditHost();
    const tool = new Tool();
    const [result] = await run(host, tool, { modern });
    expect(result?.isError).toBeFalsy();
    expect(tool.negotiated).toEqual([true]);
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(new Set(host.records().map((record) => record.event.session_id))).toEqual(new Set([tool.sessions[0]]));
    expect(host.anomalies()).toEqual([]);
    expect(verifyLedger(host.records()).ok).toBe(true);
  });

  it('concurrent operations of one call are all recorded', async () => {
    const host = auditHost();
    const tool = new Tool(TOOL_CAPABILITY, { operations: 4 });
    const [result] = await run(host, tool, { modern });
    expect(result?.isError).toBeFalsy();
    expect(tool.performed).toBe(4);
    expect(host.records()).toHaveLength(8);
    expect(host.anomalies()).toEqual([]);
  });

  it('Level 2 numbers each call from zero (§7.4)', async () => {
    const key = generateToolKey('tool-key');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);
    const host = auditHost(l2(), { verifier: new KeyRegistryVerifier(registry) });
    const tool = new Tool(l2(), { operations: 3, signer: Ed25519Signer.fromToolKey(key) });
    await run(host, tool, { modern, calls: 2 });
    expect(tool.sessions).toHaveLength(2);
    for (const sessionId of tool.sessions) {
      const numbers = host
        .records()
        .filter((record) => record.event.session_id === sessionId)
        .map((record) => record.event.signer_seq as number)
        .sort((a, b) => a - b);
      expect(numbers).toEqual([0, 1, 2, 3, 4, 5]);
    }
    expect(host.anomalies()).toEqual([]);
    expect(verifyLedger(host.records()).ok).toBe(true);
  });

  it('a tool that requires a countersignature acts on a countersigned accept (§5.2)', async () => {
    const hostKey = generateToolKey('host-key');
    const hostRegistry = new KeyRegistry(KeyRole.HOST);
    hostRegistry.register(hostKey.keyId, hostKey.publicKey, SignatureAlgorithm.ED25519);
    const countersigning = { ...TOOL_CAPABILITY, countersign: Countersign.HOST };
    const host = auditHost(countersigning, {
      countersigner: new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey),
    });
    const tool = new Tool(countersigning, { countersignatureRegistry: hostRegistry });
    const [result] = await run(host, tool, { modern });
    expect(result?.isError).toBeFalsy();
    expect(tool.performed).toBe(1);
    expect(host.records().every((record) => record.log_id === 'tenant-a')).toBe(true);
  });

  it('a host that cannot record fails the operation closed (§7.2)', async () => {
    const host = auditHost();
    host.persistenceAvailable = false;
    const tool = new Tool();
    const [result] = await run(host, tool, { modern });
    expect(result?.isError).toBe(true);
    expect(tool.performed).toBe(0);
    expect(host.records()).toEqual([]);
  });

  it('an ordinary host is served as ordinary MCP and the tool records for itself (§6.2)', async () => {
    const tool = new Tool();
    const [result] = await run(undefined, tool, { modern });
    expect(result?.isError).toBeFalsy();
    expect(tool.negotiated).toEqual([false]);
    expect(tool.fallback.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(tool.fallback.anomalies()).toEqual([]);
  });

  it('an unnegotiated call refuses to send (§6.2)', async () => {
    const tool = new Tool();
    await run(undefined, tool, { modern });
    expect(tool.negotiated).toEqual([false]);
    expect(tool.refused).toEqual(['UnnegotiatedSendError', 'UnnegotiatedSendError']);
  });
});

/** The `_meta` a 2026-07-28 client puts on a request, with this extension's object when given. */
function modernMeta(sessionId?: string, responses?: Record<string, unknown>): Record<string, unknown> {
  const meta: Record<string, unknown> = {
    'io.modelcontextprotocol/protocolVersion': MODERN_VERSION,
    'io.modelcontextprotocol/clientCapabilities': { extensions: auditExtension(TOOL_CAPABILITY) },
    'io.modelcontextprotocol/clientInfo': { name: 'host', version: '0.0.0' },
  };
  if (sessionId !== undefined) {
    meta[EXTENSION_ID] = responses === undefined ? { session_id: sessionId } : { session_id: sessionId, responses };
  }
  return meta;
}

/** A 2026-07-28 `tools/call` from a host that audits it, or a retry of one. */
function toolsCall(
  id: number,
  options: { sessionId: string; state?: string; responses?: Record<string, unknown> },
): JsonRpcFrame {
  const params: Record<string, unknown> = {
    name: 'read_customers',
    arguments: {},
    _meta: modernMeta(options.sessionId, options.responses),
  };
  if (options.state !== undefined) {
    params.requestState = options.state;
  }
  return { jsonrpc: '2.0', id, method: 'tools/call', params };
}

function attemptEvent(sessionId: string): Record<string, unknown> {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    spec_version: SPEC_VERSION,
    ts: '2026-07-15T00:00:01.000Z',
    session_id: sessionId,
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
  };
}

/** A peer at the far end of a wire, reading and writing the JSON-RPC frames directly. */
class BareWire {
  readonly frames: JsonRpcFrame[] = [];
  #read = 0;

  constructor(readonly send: (frame: JsonRpcFrame) => Promise<void>) {}

  /** A peer on the far end of `wire`. */
  static on(wire: InMemoryTransport): BareWire {
    const peer = new BareWire((frame) => wire.send(frame as never));
    wire.onmessage = (message) => {
      peer.frames.push(message as JsonRpcFrame);
    };
    return peer;
  }

  /** The next frame on the wire, bounded. */
  async next(): Promise<JsonRpcFrame> {
    await until(() => this.frames.length > this.#read);
    const frame = this.frames[this.#read] as JsonRpcFrame;
    this.#read += 1;
    return frame;
  }
}

/** A tool server whose peer is this test. */
async function toolOnABareWire(
  tool: Tool,
  options: { requestTimeoutMs?: number } = {},
): Promise<{ peer: BareWire; close: () => Promise<void> }> {
  const [peerWire, toolWire] = InMemoryTransport.createLinkedPair();
  const transport = new McpAuditTransport(toolWire, tool.declares, options);
  const peer = BareWire.on(peerWire);
  await peerWire.start();
  const server = serveTool(transport, tool);
  return { peer, close: () => server.close() };
}

/** A host seam whose tool side is this test, and whose client side is too. */
async function hostOnABareWire(
  endpoint: AuditEndpoint,
  options: { requestTimeoutMs?: number } = {},
): Promise<{ tool: BareWire; client: BareWire; close: () => Promise<void> }> {
  const [hostWire, toolWire] = InMemoryTransport.createLinkedPair();
  const receiver = new McpAuditReceiver(hostWire, endpoint, options);
  const tool = BareWire.on(toolWire);
  const client = new BareWire((frame) => receiver.send(frame));
  receiver.onmessage = (message) => {
    client.frames.push(message);
  };
  await Promise.all([receiver.start(), toolWire.start()]);
  return { tool, client, close: () => receiver.close() };
}

describe('the MRTR binding (§6.4)', () => {
  it('the client sees one ordinary result', async () => {
    const tool = new Tool(TOOL_CAPABILITY, { operations: 2 });
    const [result] = await run(auditHost(), tool, { modern: true });
    expect(textOf(result as CallResult)).toBe('read 2 rows');
  });

  it('a round the host never retries fails the operation closed', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool, { requestTimeoutMs: 200 });
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    expect(round.result?.resultType).toBe('input_required');
    await until(() => tool.negotiated.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(tool.performed).toBe(0);
    await wire.close();
  });

  it('a replayed retry is refused and does not run the operation again (at most once)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    const state = round.result?.requestState as string;
    const carried = (round.result?._meta as Record<string, { events: Record<string, unknown>[] }>)[EXTENSION_ID];
    const responses = { [String(carried?.events[0]?.id)]: ACCEPT };
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state, responses }));
    const final = await wire.peer.next();
    expect(final.id).toBe(2);
    expect(final.result).toBeDefined();
    expect(tool.performed).toBe(1);
    await wire.peer.send(toolsCall(3, { sessionId: SESSION, state, responses }));
    const refused = await wire.peer.next();
    expect(refused.id).toBe(3);
    expect(refused.error).toBeDefined();
    expect(tool.performed).toBe(1);
    await wire.close();
  });

  it('the final result carries the trailing outcome', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    const carried = (round.result?._meta as Record<string, { session_id: string; events: Record<string, unknown>[] }>)[
      EXTENSION_ID
    ];
    expect(carried?.session_id).toBe(SESSION);
    expect(carried?.events.map((event) => event.outcome)).toEqual(['attempted']);
    const attempt = carried?.events[0] as Record<string, unknown>;
    const host = auditHost();
    host.openSession(SESSION);
    const answer = await host.handleAttempt(attempt, SESSION);
    await wire.peer.send(
      toolsCall(2, {
        sessionId: SESSION,
        state: round.result?.requestState as string,
        responses: { [String(attempt.id)]: answer },
      }),
    );
    const final = await wire.peer.next();
    expect([undefined, 'complete']).toContain(final.result?.resultType);
    const trailing = (final.result?._meta as Record<string, { events: Record<string, unknown>[] }>)[EXTENSION_ID];
    expect(trailing?.events.map((event) => event.outcome)).toEqual(['success']);
    await wire.close();
  });

  it('a round that also asks the client for input goes up, and the answers follow its retry', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    await wire.client.send({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_customers', arguments: {}, _meta: modernMeta() },
    });
    const outgoing = await wire.tool.next();
    const sessionId = (outgoing.params?._meta as Record<string, { session_id: string }>)[EXTENSION_ID]
      ?.session_id as string;
    const attempt = attemptEvent(sessionId);
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: {
        resultType: 'input_required',
        inputRequests: { q: { method: 'elicitation/create', params: { message: 'ok?' } } },
        requestState: 'tool-state',
        _meta: { [EXTENSION_ID]: { session_id: sessionId, events: [attempt] } },
      },
    });
    const surfaced = await wire.client.next();
    expect(surfaced.result?.inputRequests).toBeDefined();
    await wire.client.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'read_customers',
        arguments: {},
        requestState: 'tool-state',
        inputResponses: { q: { action: 'accept' } },
        _meta: modernMeta(),
      },
    });
    const forwarded = await wire.tool.next();
    const carried = (
      forwarded.params?._meta as Record<string, { session_id: string; responses: Record<string, AttemptResponse> }>
    )[EXTENSION_ID];
    expect(carried?.session_id).toBe(sessionId);
    expect(carried?.responses[String(attempt.id)]?.status).toBe('accept');
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted']);
    await wire.close();
  });
});

/** A host that answers only after the tool has stopped waiting: late is the same as never to it. */
class LateEndpoint implements AuditEndpoint {
  readonly capability = TOOL_CAPABILITY;
  openSession(): string {
    return SESSION;
  }
  async closeSession(): Promise<void> {}
  async handleAttempt(): Promise<AttemptResponse> {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    return unavailable();
  }
  async handleOutcome(): Promise<void> {}
}

/** A host whose audit subsystem stalls on every decision. */
class StalledEndpoint extends LateEndpoint {
  override async handleAttempt(): Promise<AttemptResponse> {
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    return unavailable();
  }
}

describe.each(BINDINGS)('a stalled endpoint: %s', (_name, modern) => {
  it('does not hold the result from the client; the host bounds its own wait', async () => {
    const tool = new Tool();
    const started = Date.now();
    const [result] = await run(new StalledEndpoint(), tool, { modern, requestTimeoutMs: 200 });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(result?.isError).toBe(true);
    expect(tool.performed).toBe(0);
  });
});

/** A real host behind an audit subsystem that takes longer than the binding waits (field check C8). */
class LateHost implements AuditEndpoint {
  readonly capability: AuditCapability;
  constructor(
    readonly host: AuditHost,
    readonly delayMs: number,
  ) {
    this.capability = host.capability;
  }
  openSession(sessionId?: string): string {
    return this.host.openSession(sessionId);
  }
  closeSession(sessionId: string): Promise<void> {
    return this.host.closeSession(sessionId);
  }
  async handleAttempt(event: Record<string, unknown>, sessionId?: string, deadline?: number): Promise<AttemptResponse> {
    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    return this.host.handleAttempt(event, sessionId, deadline);
  }
  handleOutcome(event: unknown, sessionId?: string): Promise<void> {
    return this.host.handleOutcome(event, sessionId);
  }
}

describe.each(BINDINGS)('a decision past the deadline: %s', (_name, modern) => {
  it('records nothing, so the ledger holds the refusal alone and no anomaly blames the tool (§6.4)', async () => {
    const host = auditHost();
    const tool = new Tool();
    const [result] = await run(new LateHost(host, 600), tool, { modern, requestTimeoutMs: 200 });
    await new Promise((resolve) => setTimeout(resolve, 800));
    expect(result?.isError).toBe(true);
    expect(tool.performed).toBe(0);
    expect(host.records().map((record) => [record.event.outcome, record.event.reason])).toEqual([
      ['aborted', 'host-unavailable'],
    ]);
    expect(host.anomalies()).toEqual([]);
  });
});

describe('the initialize binding (§6.5)', () => {
  it('an attempt the host never answers fails closed (§6)', async () => {
    const tool = new Tool();
    const [result] = await run(new LateEndpoint(), tool, { modern: false, requestTimeoutMs: 200 });
    expect(result?.isError).toBe(true);
    expect(tool.performed).toBe(0);
  });

  it('an outcome sent as a request is refused and not sealed', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    await wire.tool.send({ jsonrpc: '2.0', id: 7, method: OUTCOME_METHOD, params: { id: 'e1' } });
    const frame = await wire.tool.next();
    expect(frame.id).toBe(7);
    expect(frame.error).toBeDefined();
    expect(host.records()).toEqual([]);
    await wire.close();
  });

  it('an attempt sent as a notification is dropped (§6)', async () => {
    // It has no response channel, so sealing it would record an operation never cleared.
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    await wire.tool.send({ jsonrpc: '2.0', method: ATTEMPT_METHOD, params: { id: 'e1' } });
    await wire.tool.send({ jsonrpc: '2.0', id: 'amcp-1', method: ATTEMPT_METHOD, params: { id: 'e1' } });
    const frame = await wire.tool.next();
    expect(frame.id).toBe('amcp-1');
    expect((frame.result as AttemptResponse | undefined)?.status).toBe('reject');
    expect(host.records()).toEqual([]);
    await wire.close();
  });
});

describe("the host seam reads the tool's handshake declaration (§6.1)", () => {
  function handshakeWarnings(warned: { mock: { calls: unknown[][] } }): string[] {
    return warned.mock.calls
      .map((args) => String(args[0]))
      .filter((text) => text.includes('handshake') || text.includes('requirement'));
  }

  it.each(BINDINGS)('warns once when the declaration does not fit the requirement (%s)', async (_name, modern) => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const live = await connection(auditHost(l2(), { verifier: ANY_KEY }), new Tool(TOOL_CAPABILITY), { modern });
      await live.client.listTools();
      await live.close();
      const warnings = handshakeWarnings(warned);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/outcome mismatch/);
    } finally {
      warned.mockRestore();
    }
  });

  it('warns nothing when the declaration fits', async () => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const live = await connection(auditHost(), new Tool(TOOL_CAPABILITY), { modern: false });
      await live.close();
      expect(handshakeWarnings(warned)).toEqual([]);
    } finally {
      warned.mockRestore();
    }
  });

  it('warns when the tool declared nothing, and only on the first handshake result', async () => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { tool, client, close } = await hostOnABareWire(auditHost());
    try {
      for (const id of [1, 2]) {
        await client.send({ jsonrpc: '2.0', id, method: INITIALIZE_METHOD, params: { capabilities: {} } });
        const initialize = await tool.next();
        await tool.send({ jsonrpc: '2.0', id: initialize.id, result: { capabilities: { tools: {} } } });
        await client.next();
      }
      const warnings = handshakeWarnings(warned);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/declared no auditable-mcp capability.*outcome undeclared/);
    } finally {
      await close();
      warned.mockRestore();
    }
  });
});

describe('the per-call transport', () => {
  it('asking for a call that is not in flight is refused', () => {
    const [, toolWire] = InMemoryTransport.createLinkedPair();
    const transport = new McpAuditTransport(toolWire, TOOL_CAPABILITY);
    expect(() => transport.call(99)).toThrow(UnknownCallError);
  });

  it('ids are matched by type and value: the string form of a number id names no call', async () => {
    const inner = new SpyTransport();
    const transport = new McpAuditTransport(inner, TOOL_CAPABILITY);
    const delivered: JsonRpcFrame[] = [];
    transport.onmessage = (message) => {
      delivered.push(message);
    };
    const toolsCall = (id: string | number): void =>
      inner.onmessage?.({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'read_customers' } });

    toolsCall(7);
    await vi.waitFor(() => expect(delivered).toHaveLength(1));
    expect(() => transport.call('7')).toThrow(/pass the raw JSON-RPC id/);
    expect(() => transport.call(7)).not.toThrow();

    toolsCall('7');
    await vi.waitFor(() => expect(delivered).toHaveLength(2));
    expect(transport.call('7').sessionId).not.toBe(transport.call(7).sessionId);
    expect(() => transport.call('8')).toThrow(UnknownCallError);
  });

  it('negotiating with another capability is refused (§6.1)', async () => {
    const seen: string[] = [];
    const tool = new Tool(TOOL_CAPABILITY, { negotiateWith: l2(), seen });
    await run(auditHost(), tool, { modern: true });
    expect(seen).toEqual(['McpBindingError']);
  });
});

/** Records everything a session can do to a transport, so the seam can be checked for leaks. */
class SpyTransport implements McpTransport {
  started = false;
  closed = false;
  readonly sent: JsonRpcFrame[] = [];
  protocolVersion: string | undefined;
  supportedVersions: string[] | undefined;
  readonly hasPerRequestStream = true;
  sessionId = 'session-7';
  onmessage?: (message: JsonRpcFrame, extra?: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;

  async start(): Promise<void> {
    this.started = true;
  }
  readonly options: unknown[] = [];
  async send(message: JsonRpcFrame, options?: unknown): Promise<void> {
    this.sent.push(message);
    this.options.push(options);
  }
  async close(): Promise<void> {
    this.closed = true;
  }
  setProtocolVersion(version: string): void {
    this.protocolVersion = version;
  }
  setSupportedProtocolVersions(versions: string[]): void {
    this.supportedVersions = versions;
  }
}

describe('the seam is a faithful transport (§6.2)', () => {
  it('passes every member of the transport it wraps through to the session', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);

    await seam.start();
    expect(inner.started).toBe(true);

    // The session reads this to choose how it cancels a request; reporting undefined for a transport
    // that sets it would change how ordinary MCP behaves on this connection.
    expect(seam.hasPerRequestStream).toBe(true);
    expect(seam.sessionId).toBe('session-7');

    seam.setProtocolVersion(MODERN_VERSION);
    expect(inner.protocolVersion).toBe(MODERN_VERSION);

    // Called during connect, for the header validation an HTTP transport performs.
    seam.setSupportedProtocolVersions([MODERN_VERSION, '2025-06-18']);
    expect(inner.supportedVersions).toEqual([MODERN_VERSION, '2025-06-18']);

    const onerror = (): void => undefined;
    seam.onerror = onerror;
    expect(inner.onerror).toBe(onerror);

    await seam.send({ jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(inner.sent.at(-1)?.method).toBe('ping');

    await seam.close();
    expect(inner.closed).toBe(true);
  });

  it('the host seam passes them through too', () => {
    const inner = new SpyTransport();
    const seam = new McpAuditReceiver(inner, auditHost());
    expect(seam.hasPerRequestStream).toBe(true);
    seam.setSupportedProtocolVersions([MODERN_VERSION]);
    expect(inner.supportedVersions).toEqual([MODERN_VERSION]);
  });
});

const OTHER_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc1';

type Carried = { session_id: string; events: Record<string, unknown>[] };

function carriedOf(frame: JsonRpcFrame): Carried | undefined {
  return (frame.result?._meta as Record<string, Carried> | undefined)?.[EXTENSION_ID];
}

/** Answer every attempt a round carried from a real host holding `SESSION`. */
async function answer(host: AuditHost, round: JsonRpcFrame): Promise<Record<string, unknown>> {
  const responses: Record<string, unknown> = {};
  for (const event of carriedOf(round)?.events ?? []) {
    if (event.outcome === 'attempted') {
      responses[String(event.id)] = await host.handleAttempt(event, SESSION);
    } else {
      await host.handleOutcome(event, SESSION);
    }
  }
  return responses;
}

function sessionHost(): AuditHost {
  const host = auditHost();
  host.openSession(SESSION);
  return host;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

/** True once `call` stops throwing. */
function reachable(call: () => unknown): () => boolean {
  return () => {
    try {
      call();
      return true;
    } catch {
      return false;
    }
  };
}

describe('the tool seam after review (§6.4, §6.5)', () => {
  it('a declaration equal field by field negotiates whatever its key order (§6.1)', async () => {
    const seen: string[] = [];
    const reordered = {
      countersign: TOOL_CAPABILITY.countersign,
      attempt: TOOL_CAPABILITY.attempt,
      level: TOOL_CAPABILITY.level,
      spec_version: TOOL_CAPABILITY.spec_version,
    } as AuditCapability;
    const tool = new Tool(TOOL_CAPABILITY, { negotiateWith: reordered, seen });
    await run(auditHost(), tool, { modern: true });
    expect(seen).toEqual([]);
    expect(tool.negotiated).toEqual([true]);
  });

  it('an attempt that timed out is forgotten, and its late answer is dropped, not shown to the session (§6.5)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY, { requestTimeoutMs: 20 });
    const delivered: JsonRpcFrame[] = [];
    seam.onmessage = (message) => {
      delivered.push(message);
    };
    const declared = { capabilities: { extensions: auditExtension(TOOL_CAPABILITY) } };
    inner.onmessage?.({ jsonrpc: '2.0', id: 0, method: 'initialize', params: declared });
    inner.onmessage?.({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_customers', arguments: {}, _meta: { [EXTENSION_ID]: { session_id: SESSION } } },
    });
    await until(() => delivered.length === 2);
    const audit = seam.call(1);
    expect(audit.negotiate(TOOL_CAPABILITY).negotiated).toBe(true);
    expect((await audit.sendAttempt(attemptEvent(SESSION))).status).toBe('unavailable');
    const sent = inner.sent.find((frame) => frame.method === ATTEMPT_METHOD);
    inner.onmessage?.({ jsonrpc: '2.0', id: sent?.id as string, result: ACCEPT });
    inner.onmessage?.({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'x' } });
    await until(() => delivered.length === 3);
    expect(delivered.map((frame) => frame.id ?? frame.method)).toEqual([0, 1, 'notifications/message']);
  });

  it('a retry that carries another session answers none of the round (§6.4)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    const responses = { [String(carriedOf(round)?.events[0]?.id)]: ACCEPT };
    const state = round.result?.requestState as string;
    await wire.peer.send(toolsCall(2, { sessionId: OTHER_SESSION, state, responses }));
    const final = await wire.peer.next();
    expect(final.id).toBe(2);
    expect(tool.performed).toBe(0);
    expect(carriedOf(final)?.events.map((event) => event.reason)).toEqual(['host-unavailable']);
    await wire.close();
  });

  it('every round token carries the fixed prefix, and an unknown one is refused undispatched (§6.4)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION, state: `${ROUND_TOKEN_PREFIX}forged` }));
    const refused = await wire.peer.next();
    expect(refused.id).toBe(1);
    expect(refused.error?.code).toBe(-32602);
    expect(tool.negotiated).toEqual([]);
    await wire.peer.send(toolsCall(2, { sessionId: SESSION }));
    const round = await wire.peer.next();
    expect(String(round.result?.requestState).startsWith(ROUND_TOKEN_PREFIX)).toBe(true);
    await wire.close();
  });

  it('a call that ends in an error sends its outcomes in a round of their own first (§6.4)', async () => {
    const host = sessionHost();
    const tool = new Tool(TOOL_CAPABILITY, { throwAfter: true });
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    const state = round.result?.requestState as string;
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state, responses: await answer(host, round) }));
    const outcomes = await wire.peer.next();
    expect(outcomes.id).toBe(2);
    expect(outcomes.result?.resultType).toBe('input_required');
    expect(carriedOf(outcomes)?.events.map((event) => event.outcome)).toEqual(['success']);
    await answer(host, outcomes);
    await wire.peer.send(toolsCall(3, { sessionId: SESSION, state: outcomes.result?.requestState as string }));
    const error = await wire.peer.next();
    expect(error.id).toBe(3);
    expect(error.error).toBeDefined();
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    await wire.close();
  });

  it('a result reached while a round is out goes on that round’s retry, with its aborted outcome (§6.4)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool, { requestTimeoutMs: 300 });
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    await sleep(400);
    const responses = { [String(carriedOf(round)?.events[0]?.id)]: ACCEPT };
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state: round.result?.requestState as string, responses }));
    const final = await wire.peer.next();
    expect(final.id).toBe(2);
    expect(final.result?.isError).toBe(true);
    expect(carriedOf(final)?.events.map((event) => event.reason)).toEqual(['host-unavailable']);
    // The late accept does not release the operation the tool already aborted (§6 at most once).
    expect(tool.performed).toBe(0);
    await wire.close();
  });

  it('an error reached while a round is out keeps its aborted outcome, then the error (§6.4)', async () => {
    const tool = new Tool(TOOL_CAPABILITY, { throwAfter: true });
    const wire = await toolOnABareWire(tool, { requestTimeoutMs: 300 });
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    await sleep(400);
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state: round.result?.requestState as string }));
    const outcomes = await wire.peer.next();
    expect(outcomes.id).toBe(2);
    expect(carriedOf(outcomes)?.events.map((event) => event.reason)).toEqual(['host-unavailable']);
    await wire.peer.send(toolsCall(3, { sessionId: SESSION, state: outcomes.result?.requestState as string }));
    const error = await wire.peer.next();
    expect(error.id).toBe(3);
    expect(error.error).toBeDefined();
    await wire.close();
  });

  it('a retry settles only the attempts its round carried (§6.4)', async () => {
    const host = sessionHost();
    const tool = new Tool(TOOL_CAPABILITY, { operations: 2, staggerMs: 50 });
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const first = await wire.peer.next();
    expect(carriedOf(first)?.events).toHaveLength(1);
    await sleep(150);
    let round = first;
    let id = 2;
    let final: JsonRpcFrame | undefined;
    while (final === undefined) {
      const responses = await answer(host, round);
      await wire.peer.send(
        toolsCall(id, { sessionId: SESSION, state: round.result?.requestState as string, responses }),
      );
      const next = await wire.peer.next();
      id += 1;
      if (next.result?.resultType === 'input_required') {
        round = next;
      } else {
        final = next;
      }
    }
    await answer(host, final);
    expect(tool.performed).toBe(2);
    expect(final.result?.isError).toBeFalsy();
    expect(host.anomalies()).toEqual([]);
    await wire.close();
  });

  it('a cancelled call answers its attempts as unanswered and closes its rounds (§6.3)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    await wire.peer.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
    const responses = { [String(carriedOf(round)?.events[0]?.id)]: ACCEPT };
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state: round.result?.requestState as string, responses }));
    const refused = await wire.peer.next();
    expect(refused.id).toBe(2);
    expect(refused.error?.code).toBe(-32602);
    await sleep(50);
    expect(tool.performed).toBe(0);
    await wire.close();
  });

  it('an unnegotiated call mints its own session, never the peer’s (§6.3)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    const call = toolsCall(1, { sessionId: SESSION });
    call.params = { ...call.params, task: { ttl: 1000 } };
    await wire.peer.send(call);
    const final = await wire.peer.next();
    expect(final.id).toBe(1);
    expect(tool.negotiated).toEqual([false]);
    expect(tool.sessions[0]).not.toBe(SESSION);
    expect(tool.fallback.records()[0]?.event.session_id).toBe(tool.sessions[0]);
    await wire.close();
  });

  it('numbering is one object per session across the calls that carry it (§7.4)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
    seam.onmessage = () => undefined;
    inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
    inner.onmessage?.(toolsCall(2, { sessionId: SESSION }));
    inner.onmessage?.(toolsCall(3, { sessionId: OTHER_SESSION }));
    await until(reachable(() => seam.call(3)));
    expect(seam.call(1).numbering).toBe(seam.call(1).numbering);
    expect(seam.call(1).numbering).toBe(seam.call(2).numbering);
    expect(seam.call(3).numbering).not.toBe(seam.call(1).numbering);
  });

  it('JSON-RPC ids 1 and "1" are two calls (§6.3)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
    seam.onmessage = () => undefined;
    inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
    inner.onmessage?.({ ...toolsCall(1, { sessionId: OTHER_SESSION }), id: '1' });
    // Each raw id names its own call; neither is taken for the other.
    await until(() => {
      try {
        seam.call('1');
        return true;
      } catch {
        return false;
      }
    });
    const numeric = seam.call(1);
    const text = seam.call('1');
    numeric.negotiate(TOOL_CAPABILITY);
    text.negotiate(TOOL_CAPABILITY);
    expect(numeric.sessionId).toBe(SESSION);
    expect(text.sessionId).toBe(OTHER_SESSION);
  });
});

describe('the host seam after review (§6.3, §6.4, §6.5)', () => {
  async function openCall(
    wire: { tool: BareWire; client: BareWire },
    id: number | string,
    params: Record<string, unknown> = { name: 'read_customers', arguments: {} },
  ): Promise<string> {
    await wire.client.send({ jsonrpc: '2.0', id, method: 'tools/call', params });
    const outgoing = await wire.tool.next();
    return (outgoing.params?._meta as Record<string, { session_id: string }>)[EXTENSION_ID]?.session_id as string;
  }

  it('an event of a session not in flight on this connection is refused (§6.5)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const mine = await openCall(wire, 1);
    const elsewhere = host.openSession();
    await wire.tool.send({ jsonrpc: '2.0', id: 'a-1', method: ATTEMPT_METHOD, params: attemptEvent(elsewhere) });
    expect((await wire.tool.next()).result).toEqual({ status: 'reject', reason: 'replay-detected' });
    await wire.tool.send({
      jsonrpc: '2.0',
      method: OUTCOME_METHOD,
      params: { ...attemptEvent(elsewhere), outcome: 'aborted', reason: 'host-rejected' },
    });
    await wire.tool.send({ jsonrpc: '2.0', id: 'a-2', method: ATTEMPT_METHOD, params: attemptEvent(mine) });
    expect(((await wire.tool.next()).result as AttemptResponse).status).toBe('accept');
    expect(host.records().map((record) => record.event.session_id)).toEqual([mine]);
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual(['replay-detected', 'replay-detected']);
    await wire.close();
  });

  it('where the transport relates the request, the related call’s session is the expected one (§6.5)', async () => {
    const host = auditHost();
    const inner = new SpyTransport();
    const seam = new McpAuditReceiver(inner, host);
    seam.onmessage = () => undefined;
    await seam.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_customers' } });
    await seam.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_customers' } });
    const sessions = inner.sent.map(
      (frame) => (frame.params?._meta as Record<string, { session_id: string }>)[EXTENSION_ID]?.session_id,
    );
    inner.onmessage?.(
      { jsonrpc: '2.0', id: 'a-1', method: ATTEMPT_METHOD, params: attemptEvent(sessions[1] as string) },
      { relatedRequestId: 1 },
    );
    await until(() => inner.sent.length === 3);
    expect(inner.sent[2]?.result).toEqual({ status: 'reject', reason: 'replay-detected' });
  });

  it('a slow decision in one session holds up neither another session nor other traffic', async () => {
    const host = auditHost();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let slow: string | undefined;
    const endpoint: AuditEndpoint = {
      capability: host.capability,
      openSession: (sessionId) => host.openSession(sessionId),
      closeSession: (sessionId) => host.closeSession(sessionId),
      handleAttempt: async (event, sessionId) => {
        if (event.session_id === slow) {
          await gate;
        }
        return host.handleAttempt(event, sessionId);
      },
      handleOutcome: (event, sessionId) => host.handleOutcome(event, sessionId),
    };
    const wire = await hostOnABareWire(endpoint);
    slow = await openCall(wire, 1);
    const fast = await openCall(wire, 2);
    await wire.tool.send({ jsonrpc: '2.0', id: 'a-1', method: ATTEMPT_METHOD, params: attemptEvent(slow) });
    await wire.tool.send({
      jsonrpc: '2.0',
      method: OUTCOME_METHOD,
      params: { ...attemptEvent(slow), outcome: 'success' },
    });
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 'a-2',
      method: ATTEMPT_METHOD,
      params: { ...attemptEvent(fast), id: '00000000-0000-4000-8000-000000000002' },
    });
    await wire.tool.send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'x' } });
    expect((await wire.tool.next()).id).toBe('a-2');
    expect((await wire.client.next()).method).toBe('notifications/message');
    release();
    expect((await wire.tool.next()).id).toBe('a-1');
    await until(() => host.records().length === 3);
    // Within the slow session the outcome waited for its attempt, so it correlated.
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'attempted', 'success']);
    expect(host.anomalies()).toEqual([]);
    await wire.close();
  });

  it('a call that asks for more rounds than the limit ends with an error to the client (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await openCall(wire, 7, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    let requestId: string | number = 7;
    for (let round = 0; round <= MAX_ROUNDS_PER_CALL; round += 1) {
      await wire.tool.send({
        jsonrpc: '2.0',
        id: requestId,
        result: { resultType: 'input_required', requestState: 's' },
      });
      if (round < MAX_ROUNDS_PER_CALL) {
        requestId = (await wire.tool.next()).id as string | number;
      }
    }
    const answered = await wire.client.next();
    expect(answered.id).toBe(7);
    expect(answered.error?.code).toBe(-32603);
    expect(answered.error?.message).toBe('the tool exceeded the limit of 256 audit rounds for one call');
    expect(wire.tool.frames).toHaveLength(MAX_ROUNDS_PER_CALL + 1);
    expect(await host.handleAttempt(attemptEvent(sessionId), sessionId)).toEqual({
      status: 'reject',
      reason: 'replay-detected',
    });
    await wire.close();
  });

  it('a round held for the client ends on the client’s retry id, and cancels by it (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await openCall(wire, 1, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: {
        resultType: 'input_required',
        inputRequests: { q: { method: 'elicitation/create', params: { message: 'ok?' } } },
        requestState: 'tool-state',
        _meta: { [EXTENSION_ID]: { session_id: sessionId, events: [attemptEvent(sessionId)] } },
      },
    });
    expect((await wire.client.next()).id).toBe(1);
    const retry = {
      name: 'read_customers',
      arguments: {},
      requestState: 'tool-state',
      inputResponses: { q: { action: 'accept' } },
      _meta: modernMeta(),
    };
    await wire.client.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: retry });
    expect((await wire.tool.next()).id).toBe(2);
    await wire.tool.send({ jsonrpc: '2.0', id: 2, result: { content: [] } });
    expect((await wire.client.next()).id).toBe(2);

    const cancelled = await openCall(wire, 3, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    await wire.client.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 3 } });
    expect((await wire.tool.next()).params?.requestId).toBe(3);
    expect((await host.handleAttempt(attemptEvent(cancelled), cancelled)).status).toBe('reject');
    await wire.close();
  });

  it('a task-augmented call is not issued an audit session (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    await wire.client.send({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_customers', arguments: {}, task: { ttl: 1000 } },
    });
    const outgoing = await wire.tool.next();
    expect((outgoing.params?._meta as Record<string, unknown> | undefined)?.[EXTENSION_ID]).toBeUndefined();
    await wire.close();
  });
});

/** An endpoint over `host` that counts what the seam asks of it, and can hold every decision. */
function watched(host: AuditHost, options: { gated?: boolean } = {}) {
  let open: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    open = resolve;
  });
  const state = { opened: 0, closed: [] as string[], waiting: 0, release: () => open() };
  const endpoint: AuditEndpoint = {
    capability: host.capability,
    openSession: (sessionId) => {
      state.opened += 1;
      return host.openSession(sessionId);
    },
    closeSession: async (sessionId) => {
      await host.closeSession(sessionId);
      state.closed.push(sessionId);
    },
    handleAttempt: async (event, sessionId) => {
      if (options.gated === true) {
        state.waiting += 1;
        await gate;
      }
      return host.handleAttempt(event, sessionId);
    },
    handleOutcome: (event, sessionId) => host.handleOutcome(event, sessionId),
  };
  return { endpoint, state };
}

/** A retry of the tool's own `input_required` round from a client that declares nothing on it (§6.4). */
function bareRetry(id: number, sessionId: string, state: string): JsonRpcFrame {
  return {
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: {
      name: 'read_customers',
      arguments: {},
      requestState: state,
      inputResponses: { q: { action: 'accept' } },
      _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN_VERSION, [EXTENSION_ID]: { session_id: sessionId } },
    },
  };
}

const OWN_ROUND = {
  resultType: 'input_required',
  inputRequests: { q: { method: 'elicitation/create', params: { message: 'ok?' } } },
  requestState: 'tool-state',
};

describe('the host seam, second review (§6.3, §6.4)', () => {
  async function open(
    wire: { tool: BareWire; client: BareWire },
    id: number,
    params: Record<string, unknown> = { name: 'read_customers', arguments: {} },
  ): Promise<string> {
    await wire.client.send({ jsonrpc: '2.0', id, method: 'tools/call', params });
    const outgoing = await wire.tool.next();
    return (outgoing.params?._meta as Record<string, { session_id: string }>)[EXTENSION_ID]?.session_id as string;
  }

  function success(sessionId: string): Record<string, unknown> {
    return { ...attemptEvent(sessionId), outcome: 'success' };
  }

  it('a cancellation closes the session behind the audit work that arrived before it (§6.3)', async () => {
    const host = auditHost();
    const { endpoint, state } = watched(host, { gated: true });
    const wire = await hostOnABareWire(endpoint);
    const sessionId = await open(wire, 1);
    await wire.tool.send({ jsonrpc: '2.0', id: 'a-1', method: ATTEMPT_METHOD, params: attemptEvent(sessionId) });
    await wire.tool.send({ jsonrpc: '2.0', method: OUTCOME_METHOD, params: success(sessionId) });
    await until(() => state.waiting === 1);
    await wire.client.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
    expect((await wire.tool.next()).method).toBe('notifications/cancelled');
    state.release();
    expect(((await wire.tool.next()).result as AttemptResponse).status).toBe('accept');
    await until(() => state.closed.length === 1);
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(host.anomalies()).toEqual([]);
    await wire.close();
  });

  it('a lost connection closes each session after the audit work already queued for it (§6.3)', async () => {
    const host = auditHost();
    const { endpoint, state } = watched(host, { gated: true });
    const wire = await hostOnABareWire(endpoint);
    const sessionId = await open(wire, 1);
    await wire.tool.send({ jsonrpc: '2.0', id: 'a-1', method: ATTEMPT_METHOD, params: attemptEvent(sessionId) });
    await wire.tool.send({ jsonrpc: '2.0', method: OUTCOME_METHOD, params: success(sessionId) });
    await until(() => state.waiting === 1);
    const closing = wire.close();
    await sleep(20);
    expect(state.closed).toEqual([]);
    state.release();
    await closing;
    expect(state.closed).toEqual([sessionId]);
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(host.anomalies()).toEqual([]);
  });

  it('a call cancelled while its round is decided is not retried, and a late response is dropped (§6.4)', async () => {
    const host = auditHost();
    const { endpoint, state } = watched(host, { gated: true });
    const wire = await hostOnABareWire(endpoint);
    const sessionId = await open(wire, 1, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: {
        resultType: 'input_required',
        requestState: 's',
        _meta: { [EXTENSION_ID]: { session_id: sessionId, events: [attemptEvent(sessionId)] } },
      },
    });
    await until(() => state.waiting === 1);
    await wire.client.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
    expect((await wire.tool.next()).method).toBe('notifications/cancelled');
    state.release();
    await until(() => state.closed.length === 1);
    await wire.tool.send({ jsonrpc: '2.0', id: 1, result: { content: [] } });
    await sleep(50);
    expect(wire.tool.frames).toHaveLength(2);
    expect(wire.client.frames).toEqual([]);
    await wire.close();
  });

  it('an input_required result without a requestState ends the call with an error (§6.4)', async () => {
    const host = auditHost();
    const { endpoint, state } = watched(host);
    const wire = await hostOnABareWire(endpoint);
    const sessionId = await open(wire, 1, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: {
        resultType: 'input_required',
        inputRequests: OWN_ROUND.inputRequests,
        _meta: { [EXTENSION_ID]: { session_id: sessionId, events: [attemptEvent(sessionId)] } },
      },
    });
    const answered = await wire.client.next();
    expect(answered.id).toBe(1);
    expect(answered.error).toEqual({ code: -32603, message: 'the tool asked for input without a requestState (§6.4)' });
    expect(answered.result).toBeUndefined();
    await until(() => state.closed.length === 1);
    expect(wire.tool.frames).toHaveLength(1);
    // The round's attempt is left undecided, so nothing is sealed for it.
    expect(host.records()).toEqual([]);
    expect(state.opened).toBe(1);
    await wire.close();
  });

  it('the round past the limit has its outcomes sealed and its attempts left undecided (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await open(wire, 7, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    const later = { ...attemptEvent(sessionId), id: '00000000-0000-4000-8000-000000000002' };
    let requestId: string | number = 7;
    for (let round = 1; round <= MAX_ROUNDS_PER_CALL + 1; round += 1) {
      const events =
        round === 1 ? [attemptEvent(sessionId)] : round === MAX_ROUNDS_PER_CALL + 1 ? [success(sessionId), later] : [];
      await wire.tool.send({
        jsonrpc: '2.0',
        id: requestId,
        result: {
          resultType: 'input_required',
          requestState: 's',
          _meta: { [EXTENSION_ID]: { session_id: sessionId, events } },
        },
      });
      if (round <= MAX_ROUNDS_PER_CALL) {
        requestId = (await wire.tool.next()).id as string | number;
      }
    }
    const answered = await wire.client.next();
    expect(answered.error).toEqual({
      code: -32603,
      message: 'the tool exceeded the limit of 256 audit rounds for one call',
    });
    expect(host.records().map((record) => [record.event.id, record.event.outcome])).toEqual([
      ['00000000-0000-4000-8000-000000000001', 'attempted'],
      ['00000000-0000-4000-8000-000000000001', 'success'],
    ]);
    expect(host.anomalies()).toEqual([]);
    await wire.close();
  });

  it('a round’s items are processed one at a time, and one that is not a valid event is refused alone (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await open(wire, 7, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    const malformed = { ...attemptEvent(sessionId), id: '00000000-0000-4000-8000-000000000002', mutates: 'yes' };
    const events = [42, malformed, attemptEvent(sessionId), null];
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 7,
      result: {
        resultType: 'input_required',
        requestState: 's',
        _meta: { [EXTENSION_ID]: { session_id: sessionId, events } },
      },
    });
    const retry = await wire.tool.next();
    const carried = (
      retry.params?._meta as Record<string, { responses: Record<string, { status: string; reason?: string }> }>
    )[EXTENSION_ID];
    expect(carried?.responses['00000000-0000-4000-8000-000000000002']).toEqual({
      status: 'reject',
      reason: 'schema-invalid',
    });
    expect(carried?.responses['00000000-0000-4000-8000-000000000001']?.status).toBe('accept');
    expect(Object.keys(carried?.responses ?? {})).toHaveLength(2);
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual([
      'schema-invalid',
      'schema-invalid',
      'schema-invalid',
    ]);
    expect(host.records()).toHaveLength(1);
    await wire.close();
  });

  it('task: null is not task augmentation, and the call is audited (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await open(wire, 1, { name: 'read_customers', arguments: {}, task: null });
    expect(sessionId).toBeTypeOf('string');
    await wire.close();
  });

  it('a client retry of a held round is answered even if it carries a task (§6.4)', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await open(wire, 1, { name: 'read_customers', arguments: {}, _meta: modernMeta() });
    const attempt = attemptEvent(sessionId);
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: { ...OWN_ROUND, _meta: { [EXTENSION_ID]: { session_id: sessionId, events: [attempt] } } },
    });
    await wire.client.next();
    await wire.client.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'read_customers',
        arguments: {},
        requestState: OWN_ROUND.requestState,
        task: { ttl: 1000 },
        _meta: modernMeta(),
      },
    });
    const forwarded = await wire.tool.next();
    const carried = (
      forwarded.params?._meta as Record<string, { session_id: string; responses: Record<string, AttemptResponse> }>
    )[EXTENSION_ID];
    expect(carried?.session_id).toBe(sessionId);
    expect(carried?.responses[String(attempt.id)]?.status).toBe('accept');
    await wire.close();
  });

  it('a tools/call whose _meta is not an object passes through untouched and untracked', async () => {
    const host = auditHost();
    const { endpoint, state } = watched(host);
    const wire = await hostOnABareWire(endpoint);
    const params = { name: 'read_customers', arguments: {}, _meta: 'opaque' };
    await wire.client.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params });
    expect((await wire.tool.next()).params).toEqual(params);
    const result = { content: [], _meta: { [EXTENSION_ID]: { session_id: 'x', events: [attemptEvent('x')] } } };
    await wire.tool.send({ jsonrpc: '2.0', id: 1, result });
    expect((await wire.client.next()).result).toEqual(result);
    expect(state.opened).toBe(0);
    expect(host.records()).toEqual([]);
    await wire.close();
  });
});

describe('the tool seam, second review (§6.3, §6.4)', () => {
  it('a retry of the tool’s own input_required round keeps the pinned result and numbering (§6.1, §6.4)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
    seam.onmessage = () => undefined;
    inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
    await until(reachable(() => seam.call(1)));
    const first = seam.call(1);
    expect(first.negotiate(TOOL_CAPABILITY).negotiated).toBe(true);
    await seam.send({ jsonrpc: '2.0', id: 1, result: OWN_ROUND });
    inner.onmessage?.(bareRetry(2, SESSION, OWN_ROUND.requestState));
    await until(reachable(() => seam.call(2)));
    const second = seam.call(2);
    expect(second.hostCapability).toEqual(TOOL_CAPABILITY);
    expect(second.negotiate(TOOL_CAPABILITY).negotiated).toBe(true);
    expect(second.sessionId).toBe(SESSION);
    expect(second.numbering).toBe(first.numbering);
    await seam.send({ jsonrpc: '2.0', id: 2, result: { content: [] } });
    // The call has ended, so the session's state is gone: a later request starts from nothing.
    inner.onmessage?.(toolsCall(3, { sessionId: SESSION }));
    await until(reachable(() => seam.call(3)));
    expect(seam.call(3).numbering).not.toBe(first.numbering);
  });

  it('an idle session outlives the request timeout, so a late retry keeps its numbering (§6.4)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY, { requestTimeoutMs: 30 });
    seam.onmessage = () => undefined;
    inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
    await until(reachable(() => seam.call(1)));
    const first = seam.call(1);
    first.negotiate(TOOL_CAPABILITY);
    await seam.send({ jsonrpc: '2.0', id: 1, result: OWN_ROUND });
    await sleep(80);
    inner.onmessage?.(bareRetry(2, SESSION, OWN_ROUND.requestState));
    await until(reachable(() => seam.call(2)));
    expect(seam.call(2).numbering).toBe(first.numbering);
    expect(seam.call(2).negotiate(TOOL_CAPABILITY).negotiated).toBe(true);
  });

  it('beyond the idle bound the least recently idle session is evicted, never a live one', async () => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const inner = new SpyTransport();
      const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
      seam.onmessage = () => undefined;
      const session = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
      inner.onmessage?.(toolsCall(0, { sessionId: session(0) }));
      await until(reachable(() => seam.call(0)));
      const live = seam.call(0).numbering;
      const numberings: SessionNumbering[] = [];
      for (let n = 1; n <= MAX_IDLE_SESSIONS + 1; n += 1) {
        inner.onmessage?.(toolsCall(n, { sessionId: session(n) }));
        await until(reachable(() => seam.call(n)));
        numberings.push(seam.call(n).numbering);
        await seam.send({ jsonrpc: '2.0', id: n, result: OWN_ROUND });
      }
      expect(warned.mock.calls.filter((call) => String(call[0]).includes(session(1)))).toHaveLength(1);
      inner.onmessage?.(bareRetry(5000, session(1), OWN_ROUND.requestState));
      inner.onmessage?.(bareRetry(5001, session(2), OWN_ROUND.requestState));
      await until(reachable(() => seam.call(5001)));
      expect(seam.call(5000).numbering).not.toBe(numberings[0]);
      expect(seam.call(5001).numbering).toBe(numberings[1]);
      expect(seam.call(0).numbering).toBe(live);
    } finally {
      warned.mockRestore();
    }
  });

  it('a tool’s own requestState under the reserved prefix is logged as an error (§6.4)', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const inner = new SpyTransport();
      const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
      seam.onmessage = () => undefined;
      inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
      await until(reachable(() => seam.call(1)));
      await seam.send({ jsonrpc: '2.0', id: 1, result: { ...OWN_ROUND, requestState: `${ROUND_TOKEN_PREFIX}mine` } });
      expect(logged.mock.calls.some((call) => String(call[0]).includes('reserved'))).toBe(true);
    } finally {
      logged.mockRestore();
    }
  });

  it('task: null is not task augmentation, and the call is negotiated (§6.4)', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool);
    const call = toolsCall(1, { sessionId: SESSION });
    call.params = { ...call.params, task: null };
    await wire.peer.send(call);
    const round = await wire.peer.next();
    expect(round.result?.resultType).toBe('input_required');
    expect(tool.negotiated).toEqual([true]);
    await wire.close();
  });

  it('a cancellation naming any id the call was served under cancels it (§6.3)', async () => {
    const host = sessionHost();
    const tool = new Tool(TOOL_CAPABILITY, { operations: 3, staggerMs: 100 });
    const wire = await toolOnABareWire(tool);
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    let round = await wire.peer.next();
    for (const id of [2, 3]) {
      const responses = await answer(host, round);
      await wire.peer.send(
        toolsCall(id, { sessionId: SESSION, state: round.result?.requestState as string, responses }),
      );
      round = await wire.peer.next();
      expect(round.id).toBe(id);
      expect(round.result?.resultType).toBe('input_required');
    }
    await wire.peer.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 2 } });
    const responses = await answer(host, round);
    await wire.peer.send(toolsCall(4, { sessionId: SESSION, state: round.result?.requestState as string, responses }));
    const refused = await wire.peer.next();
    expect(refused.id).toBe(4);
    expect(refused.error?.code).toBe(-32602);
    await sleep(100);
    expect(tool.performed).toBe(2);
    expect(wire.peer.frames).toHaveLength(4);
    await wire.close();
  });

  it('after a cancellation, the handler’s late frame is not written and a new attempt is refused (§6.3)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
    const delivered: JsonRpcFrame[] = [];
    seam.onmessage = (message) => {
      delivered.push(message);
    };
    inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
    await until(() => delivered.length === 1);
    const audit = seam.call(1);
    audit.negotiate(TOOL_CAPABILITY);
    inner.onmessage?.({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
    await until(() => delivered.length === 2);
    expect((await audit.sendAttempt(attemptEvent(SESSION))).status).toBe('unavailable');
    await seam.send({ jsonrpc: '2.0', id: 1, result: { content: [] } });
    expect(inner.sent).toEqual([]);
  });
});

describe('the tool seam, cancelling a finished call', () => {
  it('a cancellation of a call waiting on its round ends it, withholds its result, and stays here (§6.3)', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditTransport(inner, TOOL_CAPABILITY);
    const delivered: JsonRpcFrame[] = [];
    seam.onmessage = (message) => {
      delivered.push(message);
    };
    inner.onmessage?.(toolsCall(1, { sessionId: SESSION }));
    await until(() => delivered.length === 1);
    const audit = seam.call(1);
    audit.negotiate(TOOL_CAPABILITY);
    const attempt = audit.sendAttempt(attemptEvent(SESSION));
    await until(() => inner.sent.length === 1);
    const round = inner.sent[0] as JsonRpcFrame;
    const finishing = seam.send({ jsonrpc: '2.0', id: 1, result: { content: [] } });
    inner.onmessage?.({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
    await finishing;
    expect((await attempt).status).toBe('unavailable');
    inner.onmessage?.(toolsCall(2, { sessionId: SESSION, state: round.result?.requestState as string }));
    await until(() => inner.sent.length === 2);
    expect(inner.sent[1]?.id).toBe(2);
    expect(inner.sent[1]?.error?.code).toBe(-32602);
    expect(delivered).toHaveLength(1);
  });
});

/** An endpoint over `host` whose decisions and seals can each be held until released. */
function gatedEndpoint(host: AuditHost, gate: { attempts?: boolean; outcomes?: boolean; forever?: boolean } = {}) {
  let open: () => void = () => {};
  const released = new Promise<void>((resolve) => {
    open = resolve;
  });
  const wait = (): Promise<void> => (gate.forever === true ? new Promise<void>(() => {}) : released);
  const state = { attempts: 0, outcomes: 0, closed: [] as string[], release: () => open() };
  const endpoint: AuditEndpoint = {
    capability: host.capability,
    openSession: (sessionId) => host.openSession(sessionId),
    closeSession: async (sessionId) => {
      state.closed.push(sessionId);
      await host.closeSession(sessionId);
    },
    handleAttempt: async (event, sessionId) => {
      state.attempts += 1;
      if (gate.attempts === true) {
        await wait();
      }
      return host.handleAttempt(event, sessionId);
    },
    handleOutcome: async (event, sessionId) => {
      state.outcomes += 1;
      if (gate.outcomes === true) {
        await wait();
      }
      return host.handleOutcome(event, sessionId);
    },
  };
  return { endpoint, state };
}

function eventNumbered(sessionId: string, n: number, outcome = 'attempted'): Record<string, unknown> {
  return { ...attemptEvent(sessionId), id: `00000000-0000-4000-8000-00000000000${n}`, outcome };
}

async function openModern(wire: { tool: BareWire; client: BareWire }, id: number): Promise<string> {
  await wire.client.send({
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: 'read_customers', arguments: {}, _meta: modernMeta() },
  });
  const outgoing = await wire.tool.next();
  return (outgoing.params?._meta as Record<string, { session_id: string }>)[EXTENSION_ID]?.session_id as string;
}

function roundOf(sessionId: string, events: unknown[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    resultType: 'input_required',
    requestState: 's',
    ...extra,
    _meta: { [EXTENSION_ID]: { session_id: sessionId, events } },
  };
}

function responsesOf(frame: JsonRpcFrame): Record<string, AttemptResponse> {
  return (frame.params?._meta as Record<string, { responses: Record<string, AttemptResponse> }>)[EXTENSION_ID]
    ?.responses as Record<string, AttemptResponse>;
}

describe('the host bounds a round by one deadline (§6.4)', () => {
  it('a round of several stalled attempts is retried within one timeout, and the tool’s result arrives', async () => {
    const tool = new Tool(TOOL_CAPABILITY, { operations: 3 });
    const started = Date.now();
    const [result] = await run(new StalledEndpoint(), tool, { modern: true, requestTimeoutMs: 200 });
    expect(Date.now() - started).toBeLessThan(1_500);
    expect(result?.isError).toBe(true);
    expect(tool.performed).toBe(0);
  });

  it('an attempt reached after the deadline is answered unavailable without reaching the endpoint', async () => {
    const host = auditHost();
    const { endpoint, state } = gatedEndpoint(host, { attempts: true });
    const wire = await hostOnABareWire(endpoint, { requestTimeoutMs: 100 });
    const sessionId = await openModern(wire, 1);
    const events = [1, 2, 3].map((n) => eventNumbered(sessionId, n));
    await wire.tool.send({ jsonrpc: '2.0', id: 1, result: roundOf(sessionId, events) });
    const retry = await wire.tool.next();
    expect(Object.values(responsesOf(retry)).map((response) => response.status)).toEqual([
      'unavailable',
      'unavailable',
      'unavailable',
    ]);
    expect(state.attempts).toBe(1);
    // The decision in progress at the deadline goes on, and is not undone.
    state.release();
    await until(() => host.records().length === 1);
    await wire.close();
  });

  it('a slow outcome seal does not hold the retry; it and the outcomes after it are sealed in order afterwards', async () => {
    const host = auditHost();
    const { endpoint, state } = gatedEndpoint(host, { outcomes: true });
    const wire = await hostOnABareWire(endpoint, { requestTimeoutMs: 100 });
    const sessionId = await openModern(wire, 1);
    await wire.tool.send({ jsonrpc: '2.0', id: 1, result: roundOf(sessionId, [eventNumbered(sessionId, 1)]) });
    const first = await wire.tool.next();
    expect(Object.values(responsesOf(first)).map((response) => response.status)).toEqual(['accept']);
    await wire.tool.send({
      jsonrpc: '2.0',
      id: first.id as string,
      result: roundOf(sessionId, [eventNumbered(sessionId, 2)]),
    });
    const second = await wire.tool.next();
    const started = Date.now();
    const events = [
      eventNumbered(sessionId, 1, 'success'),
      eventNumbered(sessionId, 3),
      eventNumbered(sessionId, 2, 'success'),
    ];
    await wire.tool.send({ jsonrpc: '2.0', id: second.id as string, result: roundOf(sessionId, events) });
    const third = await wire.tool.next();
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(responsesOf(third)).toEqual({ '00000000-0000-4000-8000-000000000003': unavailable() });
    expect(state.attempts).toBe(2);
    state.release();
    await until(() => host.records().length === 4);
    expect(host.records().map((record) => [record.event.id, record.event.outcome])).toEqual([
      ['00000000-0000-4000-8000-000000000001', 'attempted'],
      ['00000000-0000-4000-8000-000000000002', 'attempted'],
      ['00000000-0000-4000-8000-000000000001', 'success'],
      ['00000000-0000-4000-8000-000000000002', 'success'],
    ]);
    await wire.close();
  });
});

describe('the host passes results up without its audit input (§6.4)', () => {
  it('a final result loses the extension’s member, and an emptied _meta', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const first = await openModern(wire, 1);
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: { content: [], _meta: { [EXTENSION_ID]: { session_id: first, events: [] }, other: 1 } },
    });
    expect((await wire.client.next()).result).toEqual({ content: [], _meta: { other: 1 } });
    const second = await openModern(wire, 2);
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 2,
      result: { content: [], _meta: { [EXTENSION_ID]: { session_id: second, events: [] } } },
    });
    expect((await wire.client.next()).result).toEqual({ content: [] });
    await wire.close();
  });

  it('a round passed up for the client’s input loses it too', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    const sessionId = await openModern(wire, 1);
    await wire.tool.send({
      jsonrpc: '2.0',
      id: 1,
      result: roundOf(sessionId, [attemptEvent(sessionId)], {
        inputRequests: OWN_ROUND.inputRequests,
        requestState: OWN_ROUND.requestState,
      }),
    });
    const surfaced = await wire.client.next();
    expect(surfaced.result?._meta).toBeUndefined();
    expect(surfaced.result?.inputRequests).toEqual(OWN_ROUND.inputRequests);
    await wire.close();
  });
});

describe('the host closes every session when the connection ends, bounded (§6.3)', () => {
  it('a session whose work never finishes is closed within the configured timeout, and reported', async () => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const host = auditHost();
      const { endpoint, state } = gatedEndpoint(host, { outcomes: true, forever: true });
      const wire = await hostOnABareWire(endpoint, { requestTimeoutMs: 100 });
      const sessionId = await openModern(wire, 1);
      await wire.tool.send({
        jsonrpc: '2.0',
        id: 1,
        result: {
          content: [],
          _meta: { [EXTENSION_ID]: { session_id: sessionId, events: [eventNumbered(sessionId, 1, 'success')] } },
        },
      });
      // The call concluded: the client has its answer while the seal is still queued.
      expect((await wire.client.next()).id).toBe(1);
      await until(() => state.outcomes === 1);
      const started = Date.now();
      await wire.close();
      expect(Date.now() - started).toBeLessThan(1_000);
      expect(state.closed).toEqual([sessionId]);
      expect(warned.mock.calls.some((call) => String(call[0]).includes(sessionId))).toBe(true);
    } finally {
      warned.mockRestore();
    }
  });
});

describe('the host bounds the rounds it holds for the client (§6.4)', () => {
  it('beyond the bound the least recently held round is evicted: its session closes and its retry is a new call', async () => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const host = auditHost();
      const { endpoint, state } = gatedEndpoint(host);
      const wire = await hostOnABareWire(endpoint);
      const sessions: string[] = [];
      for (let n = 0; n <= MAX_IDLE_SESSIONS; n += 1) {
        const sessionId = await openModern(wire, n);
        sessions.push(sessionId);
        await wire.tool.send({
          jsonrpc: '2.0',
          id: n,
          result: { ...OWN_ROUND, requestState: `state-${n}` },
        });
        await wire.client.next();
      }
      await until(() => state.closed.length === 1);
      expect(state.closed).toEqual([sessions[0]]);
      expect(warned.mock.calls.filter((call) => String(call[0]).includes(sessions[0] as string))).toHaveLength(1);
      const retry = (id: number, requestState: string): JsonRpcFrame => ({
        jsonrpc: '2.0',
        id,
        method: 'tools/call',
        params: { name: 'read_customers', arguments: {}, requestState, _meta: modernMeta() },
      });
      await wire.client.send(retry(5000, 'state-0'));
      const evicted = (await wire.tool.next()).params?._meta as Record<
        string,
        { session_id: string; responses?: unknown }
      >;
      expect(evicted[EXTENSION_ID]?.session_id).not.toBe(sessions[0]);
      expect(evicted[EXTENSION_ID]?.responses).toBeUndefined();
      await wire.client.send(retry(5001, 'state-1'));
      const kept = (await wire.tool.next()).params?._meta as Record<
        string,
        { session_id: string; responses?: unknown }
      >;
      expect(kept[EXTENSION_ID]).toEqual({ session_id: sessions[1], responses: {} });
      await wire.close();
    } finally {
      warned.mockRestore();
    }
  });
});

describe('the tool keeps a concluded call for its round’s retry (§6.4)', () => {
  it('a retry long after the request timeout still gets the final result and its outcomes', async () => {
    const tool = new Tool();
    const wire = await toolOnABareWire(tool, { requestTimeoutMs: 50 });
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    await sleep(500);
    const responses = { [String(carriedOf(round)?.events[0]?.id)]: ACCEPT };
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state: round.result?.requestState as string, responses }));
    const final = await wire.peer.next();
    expect(final.id).toBe(2);
    expect(final.result?.isError).toBe(true);
    expect(carriedOf(final)?.events.map((event) => event.reason)).toEqual(['host-unavailable']);
    // The late accept answers an attempt already treated as unanswered, so it changes nothing.
    expect(tool.performed).toBe(0);
    await wire.close();
  });

  it('an error kept that long goes out after its outcomes-only round, each retry however late', async () => {
    const tool = new Tool(TOOL_CAPABILITY, { throwAfter: true });
    const wire = await toolOnABareWire(tool, { requestTimeoutMs: 50 });
    await wire.peer.send(toolsCall(1, { sessionId: SESSION }));
    const round = await wire.peer.next();
    await sleep(300);
    await wire.peer.send(toolsCall(2, { sessionId: SESSION, state: round.result?.requestState as string }));
    const outcomes = await wire.peer.next();
    expect(outcomes.id).toBe(2);
    expect(carriedOf(outcomes)?.events.map((event) => event.reason)).toEqual(['host-unavailable']);
    await sleep(300);
    await wire.peer.send(toolsCall(3, { sessionId: SESSION, state: outcomes.result?.requestState as string }));
    const error = await wire.peer.next();
    expect(error.id).toBe(3);
    expect(error.error).toBeDefined();
    await wire.close();
  });

  it('beyond the bound the least recently kept call is dropped, with a warning; the others are answered', async () => {
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const inner = new SpyTransport();
      const seam = new McpAuditTransport(inner, TOOL_CAPABILITY, { requestTimeoutMs: 50 });
      seam.onmessage = () => undefined;
      const session = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
      const tokens: string[] = [];
      // Each attempt fails closed after the timeout and logs it; they are awaited before the console is
      // restored, or the last ones would log after the file has torn down.
      const attempts: Promise<unknown>[] = [];
      for (let n = 0; n <= MAX_IDLE_SESSIONS; n += 1) {
        inner.onmessage?.(toolsCall(n, { sessionId: session(n) }));
        await until(reachable(() => seam.call(n)));
        const audit = seam.call(n);
        audit.negotiate(TOOL_CAPABILITY);
        attempts.push(audit.sendAttempt(eventNumbered(session(n), 1)));
        await until(() => inner.sent.length === n + 1);
        tokens.push(inner.sent[n]?.result?.requestState as string);
        await seam.send({ jsonrpc: '2.0', id: n, result: { content: [] } });
      }
      expect(warned.mock.calls.filter((call) => String(call[0]).includes(session(0)))).toHaveLength(1);
      inner.onmessage?.(toolsCall(5000, { sessionId: session(0), state: tokens[0] as string }));
      inner.onmessage?.(toolsCall(5001, { sessionId: session(1), state: tokens[1] as string }));
      await until(() => inner.sent.length === MAX_IDLE_SESSIONS + 3);
      expect(inner.sent.at(-2)).toMatchObject({ id: 5000, error: { code: -32602 } });
      expect(inner.sent.at(-1)).toMatchObject({ id: 5001, result: { content: [] } });
      await Promise.all(attempts);
    } finally {
      warned.mockRestore();
      logged.mockRestore();
    }
  });
});

/** A tool written the way most are: `McpServer.registerTool`, one audited action per call. */
function highLevelServer(transport: McpAuditTransport): McpServer {
  const server = new McpServer({ name: 'audited-tool', version: '0.0.0' });
  server.registerTool('read_customers', { description: 'read' }, async (ctx) => {
    const audit = transport.call(ctx.mcpReq.id);
    const negotiation = audit.negotiate(TOOL_CAPABILITY);
    if (!negotiation.negotiated) {
      return { content: [{ type: 'text', text: 'not audited' }], isError: true };
    }
    const session = new AmcpSession(audit, audit.sessionId);
    await using action = await session.action(
      'db.read',
      { kind: 'table', ref: 'customers' },
      { mutates: false, egress: false },
    );
    action.succeeded();
    return { content: [{ type: 'text', text: 'read 1 row' }] };
  });
  return server;
}

describe.each(BINDINGS)('a tool served through McpServer.registerTool: %s', (_name, modern) => {
  it('the host seals the attempt and its success (§6.3)', async () => {
    const host = auditHost();
    const [clientWire, serverWire] = InMemoryTransport.createLinkedPair();
    const transport = new McpAuditTransport(serverWire, TOOL_CAPABILITY);
    const server = serveStdio(() => highLevelServer(transport), { transport });
    const client = new Client(
      { name: 'host', version: '0.0.0' },
      modern ? { versionNegotiation: { mode: { pin: MODERN_VERSION } } } : {},
    );
    await client.connect(new McpAuditReceiver(clientWire, host));
    try {
      const result = await client.callTool({ name: 'read_customers', arguments: {} }, { timeout: CALL_TIMEOUT_MS });
      expect(textOf(result)).toBe('read 1 row');
      await until(() => host.records().length === 2);
      expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
      expect(host.anomalies()).toEqual([]);
      expect(verifyLedger(host.records()).ok).toBe(true);
    } finally {
      await Promise.all([client.close(), server.close()]);
    }
  });
});
