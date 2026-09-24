/** Tests for the MCP wire binding, mirroring the Python SDK's suite. */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { Server } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';
import { transportFor } from '../src/degradation';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  ATTEMPT_METHOD,
  auditExtension,
  capabilityOf,
  declare,
  declareInto,
  HandshakeNotSeenError,
  ID_PREFIX,
  type JsonRpcFrame,
  McpAuditReceiver,
  McpAuditTransport,
  McpBindingError,
  type McpTransport,
  OUTCOME_METHOD,
  UnnegotiatedSendError,
} from '../src/mcp';
import { type AttemptResponse, type AuditCapability, EXTENSION_ID, Level, SPEC_VERSION, Witness } from '../src/models';
import { AmcpAbortedError, AmcpSession } from '../src/session';
import type { AuditEndpoint, AuditTransport } from '../src/transport';
import { verifyLedger } from '../src/verify';
import { FixedDeps, MonotonicClock } from './helpers';

const TOOL_CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  witness: Witness.NONE,
};

/** A Verifiable Accept as it appears on the wire (§7.1). */
const ACCEPTED = {
  status: 'accept',
  seq: 0,
  record_hash: '0'.repeat(64),
  host_ts: '2026-07-15T00:00:01.000Z',
  previous_hash: '0'.repeat(64),
};

function auditHost(partition = 'tenant-a'): AuditHost {
  return new AuditHost(partition, TOOL_CAPABILITY, { clock: new MonotonicClock() });
}

/** A host that never answers an attempt, to exercise the bound §6 puts on the wait. */
class SilentEndpoint implements AuditEndpoint {
  readonly capability = TOOL_CAPABILITY;
  async handleAttempt(): Promise<AttemptResponse> {
    return new Promise<AttemptResponse>(() => {});
  }
  async handleOutcome(): Promise<void> {}
}

/** A host whose audit subsystem is defective, to exercise §6's result-not-error rule. */
class ThrowingEndpoint implements AuditEndpoint {
  readonly capability = TOOL_CAPABILITY;
  outcomes = 0;
  async handleAttempt(): Promise<AttemptResponse> {
    throw new Error('the ledger is on fire');
  }
  async handleOutcome(): Promise<void> {
    this.outcomes += 1;
    throw new Error('the ledger is still on fire');
  }
}

/** Stands in for a session: keeps what the seam passes through, for inspection. */
class SessionStub {
  readonly seen: JsonRpcFrame[] = [];

  attachTo(seam: McpTransport): void {
    seam.onmessage = (message) => {
      this.seen.push(message);
    };
  }

  methods(): (string | undefined)[] {
    return this.seen.map((frame) => frame.method);
  }
}

function initializeRequest(declaring?: AuditCapability): JsonRpcFrame {
  const capabilities: Record<string, unknown> = {};
  if (declaring !== undefined) {
    declareInto(capabilities, declaring);
  }
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2026-07-28', capabilities, clientInfo: { name: 'h', version: '1' } },
  };
}

/** Run one audited action over a transport, the way a tool handler would. */
async function runOneAction(transport: AuditTransport): Promise<void> {
  const session = new AmcpSession(transport, 'call-1', { deps: new FixedDeps() });
  await using action = await session.action(
    'db.read',
    { kind: 'table', ref: 'customers' },
    {
      mutates: false,
      egress: false,
    },
  );
  action.succeeded();
}

/** Let the microtask queue drain so the seam's own async handling has run. */
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
  }
}

/** Two seams facing each other with the handshake done, and no MCP session on either side. */
async function seams(
  endpoint: AuditEndpoint,
  options: { requestTimeoutMs?: number } = {},
): Promise<{ transport: McpAuditTransport; toolSide: SessionStub; close: () => Promise<void> }> {
  const [hostWire, toolWire] = InMemoryTransport.createLinkedPair();
  const receiver = new McpAuditReceiver(hostWire as unknown as McpTransport, endpoint);
  const transport = new McpAuditTransport(toolWire as unknown as McpTransport, TOOL_CAPABILITY, options);
  const toolSide = new SessionStub();
  const hostSide = new SessionStub();
  toolSide.attachTo(transport);
  hostSide.attachTo(receiver);
  await Promise.all([receiver.start(), transport.start()]);
  await receiver.send(initializeRequest());
  await settle();
  return {
    transport,
    toolSide,
    close: async () => {
      await Promise.all([receiver.close(), transport.close()]);
    },
  };
}

/** A tool seam whose peer is this test, reading and writing the JSON-RPC frames directly. */
async function toolOnABareWire(options: { requestTimeoutMs?: number } = {}): Promise<{
  transport: McpAuditTransport;
  frames: JsonRpcFrame[];
  reply: (frame: JsonRpcFrame) => Promise<void>;
  close: () => Promise<void>;
}> {
  const [peerWire, toolWire] = InMemoryTransport.createLinkedPair();
  const transport = new McpAuditTransport(toolWire as unknown as McpTransport, TOOL_CAPABILITY, options);
  new SessionStub().attachTo(transport);
  const frames: JsonRpcFrame[] = [];
  peerWire.onmessage = (message) => {
    frames.push(message as JsonRpcFrame);
  };
  await Promise.all([peerWire.start(), transport.start()]);
  await peerWire.send(initializeRequest(TOOL_CAPABILITY) as never);
  await settle();
  transport.negotiate(TOOL_CAPABILITY);
  return {
    transport,
    frames,
    reply: async (frame) => {
      await peerWire.send(frame as never);
      await settle();
    },
    close: async () => {
      await transport.close();
    },
  };
}

/** A host seam whose peer is this test, so malformed audit traffic can be put on the wire. */
async function hostOnABareWire(endpoint: AuditEndpoint): Promise<{
  frames: JsonRpcFrame[];
  sessionSaw: SessionStub;
  send: (frame: JsonRpcFrame) => Promise<void>;
  close: () => Promise<void>;
}> {
  const [hostWire, peerWire] = InMemoryTransport.createLinkedPair();
  const receiver = new McpAuditReceiver(hostWire as unknown as McpTransport, endpoint);
  const sessionSaw = new SessionStub();
  sessionSaw.attachTo(receiver);
  const frames: JsonRpcFrame[] = [];
  peerWire.onmessage = (message) => {
    frames.push(message as JsonRpcFrame);
  };
  await Promise.all([receiver.start(), peerWire.start()]);
  return {
    frames,
    sessionSaw,
    send: async (frame) => {
      await peerWire.send(frame as never);
      await settle();
    },
    close: async () => {
      await receiver.close();
    },
  };
}

/** A live MCP session between a real client and a real server, audited when `endpoint` is given. */
async function connection(
  endpoint: AuditEndpoint | undefined,
  fallbackHost: AuditHost,
): Promise<{ client: Client; transport: McpAuditTransport; close: () => Promise<void> }> {
  const [clientWire, serverWire] = InMemoryTransport.createLinkedPair();
  const transport = new McpAuditTransport(serverWire as unknown as McpTransport, TOOL_CAPABILITY);
  const fallback = new InProcessTransport(fallbackHost);

  const server = new Server({ name: 'audited-tool', version: '0.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler('tools/list', async () => ({
    tools: [{ name: 'read_customers', description: 'read', inputSchema: { type: 'object' } }],
  }));
  server.setRequestHandler('tools/call', async () => {
    const chosen = transportFor(transport.negotiate(TOOL_CAPABILITY), { negotiated: transport, fallback });
    const session = new AmcpSession(chosen, 'call-1', { deps: new FixedDeps() });
    await using action = await session.action(
      'db.read',
      { kind: 'table', ref: 'customers' },
      {
        mutates: false,
        egress: false,
      },
    );
    action.succeeded();
    return { content: [{ type: 'text', text: 'read 1 row' }] };
  });

  const client = new Client({ name: 'host', version: '0.0.0' });
  const clientTransport =
    endpoint === undefined
      ? (clientWire as unknown as McpTransport)
      : new McpAuditReceiver(clientWire as unknown as McpTransport, endpoint);

  await Promise.all([
    server.connect(transport as unknown as Parameters<Server['connect']>[0]),
    client.connect(clientTransport as unknown as Parameters<Client['connect']>[0]),
  ]);
  return {
    client,
    transport,
    close: async () => {
      await Promise.all([client.close(), server.close()]);
    },
  };
}

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

describe('handshake (§6.1)', () => {
  it('each side reads the other’s declaration', async () => {
    const host = auditHost();
    const wire = await seams(host);
    expect(wire.transport.hostCapability).toEqual(host.capability);
    await wire.close();
  });

  it('negotiating before the handshake refuses', async () => {
    const [, toolWire] = InMemoryTransport.createLinkedPair();
    const transport = new McpAuditTransport(toolWire as unknown as McpTransport, TOOL_CAPABILITY);
    expect(() => transport.negotiate(TOOL_CAPABILITY)).toThrow(HandshakeNotSeenError);
  });

  it('negotiating a capability that was not declared refuses', async () => {
    const wire = await seams(auditHost());
    expect(() => wire.transport.negotiate({ ...TOOL_CAPABILITY, level: Level.L2 })).toThrow(McpBindingError);
    await wire.close();
  });
});

describe('the per-event wire (§6)', () => {
  it('seals an attempt and returns its decision', async () => {
    const host = auditHost();
    const wire = await seams(host);
    wire.transport.negotiate(TOOL_CAPABILITY);
    await runOneAction(wire.transport);
    await settle();
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(verifyLedger(host.records()).ok).toBe(true);
    await wire.close();
  });

  it('never lets an audit frame reach the MCP session', async () => {
    const wire = await seams(auditHost());
    wire.transport.negotiate(TOOL_CAPABILITY);
    await wire.transport.sendOutcome({ ping: 'not an event' });
    await settle();
    expect(wire.toolSide.methods()).not.toContain(ATTEMPT_METHOD);
    expect(wire.toolSide.methods()).not.toContain(OUTCOME_METHOD);
    await wire.close();
  });

  it('fails closed when the host never answers', async () => {
    const wire = await seams(new SilentEndpoint(), { requestTimeoutMs: 20 });
    wire.transport.negotiate(TOOL_CAPABILITY);
    await expect(runOneAction(wire.transport)).rejects.toBeInstanceOf(AmcpAbortedError);
    await wire.close();
  });

  it('answers unavailable when the endpoint throws', async () => {
    const wire = await seams(new ThrowingEndpoint());
    wire.transport.negotiate(TOOL_CAPABILITY);
    const response = await wire.transport.sendAttempt({ event: 'whatever' });
    expect(response.status).toBe('unavailable');
    await wire.close();
  });

  it('does not answer an outcome at all when the endpoint throws', async () => {
    const endpoint = new ThrowingEndpoint();
    const wire = await seams(endpoint);
    wire.transport.negotiate(TOOL_CAPABILITY);
    await wire.transport.sendOutcome({ event: 'whatever' });
    await settle();
    expect(endpoint.outcomes).toBe(1);
    await wire.close();
  });
});

describe('the wire form (§6)', () => {
  it('sends an outcome as a notification carrying the event itself', async () => {
    const wire = await toolOnABareWire();
    const event = { event_id: 'e1', outcome: 'success' };
    await wire.transport.sendOutcome(event);
    await settle();
    const frame = wire.frames.at(-1);
    expect(frame?.method).toBe(OUTCOME_METHOD);
    expect(frame?.id).toBeUndefined();
    expect(frame?.params).toEqual(event);
    await wire.close();
  });

  it('sends an attempt as one request under an id the session cannot reach', async () => {
    const wire = await toolOnABareWire();
    const event = { event_id: 'e1', outcome: 'attempted' };
    const decided = wire.transport.sendAttempt(event);
    await settle();
    const frame = wire.frames.at(-1);
    expect(frame?.method).toBe(ATTEMPT_METHOD);
    expect(frame?.params).toEqual(event);
    expect(typeof frame?.id).toBe('string');
    expect(String(frame?.id).startsWith(ID_PREFIX)).toBe(true);
    await wire.reply({ jsonrpc: '2.0', id: frame?.id as string, result: ACCEPTED });
    expect((await decided).status).toBe('accept');
    await wire.close();
  });

  it('reads a JSON-RPC error for an attempt as a failure to record', async () => {
    const wire = await toolOnABareWire();
    const decided = wire.transport.sendAttempt({ event_id: 'e1' });
    await settle();
    const id = wire.frames.at(-1)?.id as string;
    // The error stands even beside a well-formed accept: §6 reserves errors for protocol faults, and
    // a frame carrying both is not a decision the tool may act on.
    await wire.reply({ jsonrpc: '2.0', id, error: { code: -32601, message: 'unknown method' }, result: ACCEPTED });
    expect((await decided).status).toBe('unavailable');
    await wire.close();
  });

  it('reads a decision it cannot parse as a decision it did not get', async () => {
    const wire = await toolOnABareWire();
    const decided = wire.transport.sendAttempt({ event_id: 'e1' });
    await settle();
    const id = wire.frames.at(-1)?.id as string;
    await wire.reply({ jsonrpc: '2.0', id, result: { status: 'yes' } });
    expect((await decided).status).toBe('unavailable');
    await wire.close();
  });
});

describe('malformed audit traffic (§6)', () => {
  it('refuses an outcome sent as a request, and seals nothing', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    await wire.send({ jsonrpc: '2.0', id: 7, method: OUTCOME_METHOD, params: { event_id: 'e1' } });
    const frame = wire.frames.at(-1);
    expect(frame?.error?.code).toBe(-32600);
    expect(frame?.id).toBe(7);
    expect(wire.sessionSaw.methods()).not.toContain(OUTCOME_METHOD);
    expect(host.records()).toHaveLength(0);
    await wire.close();
  });

  it('drops an attempt sent as a notification', async () => {
    const host = auditHost();
    const wire = await hostOnABareWire(host);
    await wire.send({ jsonrpc: '2.0', method: ATTEMPT_METHOD, params: { event_id: 'e1' } });
    // A well-formed attempt behind it: the first frame back proves what the notification produced.
    await wire.send({ jsonrpc: '2.0', id: 'amcp-1', method: ATTEMPT_METHOD, params: { event_id: 'e1' } });
    const frame = wire.frames.at(-1);
    expect(frame?.id).toBe('amcp-1');
    expect(frame?.result?.status).toBe('reject');
    // An MCP session cannot parse it either: passing it on would end the connection over a frame this
    // extension put there, which is the opposite of serving an unnegotiated peer (§6.2).
    expect(wire.sessionSaw.methods()).not.toContain(ATTEMPT_METHOD);
    expect(host.records()).toHaveLength(0);
    await wire.close();
  });
});

describe('closing (§7.2)', () => {
  it('fails closed on an attempt in flight when the seam closes', async () => {
    const wire = await seams(new SilentEndpoint());
    wire.transport.negotiate(TOOL_CAPABILITY);
    const decided = wire.transport.sendAttempt({ event_id: 'e1' });
    await settle();
    await wire.close();
    expect((await decided).status).toBe('unavailable');
  });

  it('fails closed on an attempt after the seam closed', async () => {
    const wire = await seams(auditHost());
    wire.transport.negotiate(TOOL_CAPABILITY);
    await wire.close();
    expect((await wire.transport.sendAttempt({ event_id: 'e1' })).status).toBe('unavailable');
    await wire.transport.sendOutcome({ event_id: 'e1' });
  });
});

describe('the send gate (§6.2)', () => {
  it('refuses to send when nothing was negotiated', async () => {
    const wire = await seams(auditHost());
    await expect(wire.transport.sendAttempt({ event: 'whatever' })).rejects.toBeInstanceOf(UnnegotiatedSendError);
    await expect(wire.transport.sendOutcome({ event: 'whatever' })).rejects.toBeInstanceOf(UnnegotiatedSendError);
    await wire.close();
  });

  it('closes the send path again on a mismatch', async () => {
    const host = new AuditHost(
      'tenant-a',
      { ...TOOL_CAPABILITY, spec_version: 'auditable-mcp/0.1' },
      { clock: new MonotonicClock() },
    );
    const wire = await seams(host);
    expect(wire.transport.negotiate(TOOL_CAPABILITY).negotiated).toBe(false);
    await expect(wire.transport.sendAttempt({ event: 'whatever' })).rejects.toBeInstanceOf(UnnegotiatedSendError);
    await wire.close();
  });
});

describe('over a live MCP session', () => {
  it('serves a tool call and records its interior', async () => {
    const wireHost = auditHost();
    const toolLocal = auditHost('tool-local');
    const live = await connection(wireHost, toolLocal);
    const result = await live.client.callTool({ name: 'read_customers', arguments: {} });
    expect(result.isError).toBeFalsy();
    expect(wireHost.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(toolLocal.records()).toHaveLength(0);
    await live.close();
  });

  it('leaves ordinary MCP working around the audit traffic', async () => {
    const live = await connection(auditHost(), auditHost('tool-local'));
    expect((await live.client.listTools()).tools.map((tool) => tool.name)).toEqual(['read_customers']);
    await live.client.callTool({ name: 'read_customers', arguments: {} });
    await live.client.ping();
    await live.close();
  });

  it('declares the extension the session never heard of', async () => {
    const live = await connection(auditHost(), auditHost('tool-local'));
    expect(capabilityOf(live.client.getServerCapabilities())).toEqual(TOOL_CAPABILITY);
    await live.close();
  });

  it('gives an ordinary host an ordinary tool and no audit frame', async () => {
    const toolLocal = auditHost('tool-local');
    const live = await connection(undefined, toolLocal);
    const result = await live.client.callTool({ name: 'read_customers', arguments: {} });
    expect(result.isError).toBeFalsy();
    expect(live.transport.negotiate(TOOL_CAPABILITY).negotiated).toBe(false);
    expect(toolLocal.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(toolLocal.records().every((record) => record.host_signature === undefined)).toBe(true);
    await live.close();
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
  async send(message: JsonRpcFrame): Promise<void> {
    this.sent.push(message);
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

    seam.setProtocolVersion('2026-07-28');
    expect(inner.protocolVersion).toBe('2026-07-28');

    // Called during connect, for the header validation an HTTP transport performs.
    seam.setSupportedProtocolVersions(['2026-07-28', '2025-06-18']);
    expect(inner.supportedVersions).toEqual(['2026-07-28', '2025-06-18']);

    const onerror = (): void => undefined;
    seam.onerror = onerror;
    expect(inner.onerror).toBe(onerror);

    await seam.send({ jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(inner.sent.at(-1)?.method).toBe('ping');

    await seam.close();
    expect(inner.closed).toBe(true);
  });

  it('the host seam passes them through too', async () => {
    const inner = new SpyTransport();
    const seam = new McpAuditReceiver(inner, auditHost());
    expect(seam.hasPerRequestStream).toBe(true);
    seam.setSupportedProtocolVersions(['2026-07-28']);
    expect(inner.supportedVersions).toEqual(['2026-07-28']);
  });
});
