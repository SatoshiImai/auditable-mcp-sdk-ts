/**
 * Round affinity over real Streamable HTTP (§6.4): the tool's HTTP entry served by `node:http` on an
 * ephemeral port, and a host built on the official `StreamableHTTPClientTransport`.
 */

import { createServer, type Server as HttpServer } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { fromJsonSchema, inputRequired, McpServer } from '@modelcontextprotocol/server';
import { afterEach, describe, expect, it } from 'vitest';
import { transportFor } from '../src/degradation';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  AFFINITY_HEADER,
  capabilityOf,
  FORWARDED_HEADER,
  instanceOfToken,
  McpAuditReceiver,
  ROUND_TOKEN_PREFIX,
} from '../src/mcp';
import {
  type AuditableMcpHandler,
  type AuditableMcpHandlerOptions,
  type AuditedServerFactory,
  authInfoOf,
  createAuditableMcpHandler,
  FORWARD_UNKNOWN_MESSAGE,
  fetchForwarder,
  NO_OPEN_ROUND_MESSAGE,
  SESSION_OPEN_MESSAGE,
} from '../src/mcp/http';
import { type AuditCapability, Countersign, EXTENSION_ID, Level, SPEC_VERSION } from '../src/models';
import { type FetchHandler, toNodeListener } from '../src/node';
import { AmcpAbortedError, AmcpSession } from '../src/session';
import type { AuditEndpoint } from '../src/transport';
import { verifyLedger } from '../src/verify';
import { MonotonicClock } from './helpers';

const CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};
const TOOL_NAME = 'read_customers';
const REGION = 'eu-west';
const REGION_HEADER = 'Mcp-Param-Region';
const PRINCIPAL_HEADER = 'x-principal';
/** The argument the tool mirrors into `Mcp-Param-Region` (SEP-2243 `x-mcp-header`). */
const REGION_PROPERTY = { type: 'string', 'x-mcp-header': 'Region' } as const;
const REGION_SCHEMA = { type: 'object', properties: { region: REGION_PROPERTY }, required: ['region'] } as const;
const HEADER_MISMATCH = -32020;
const INVALID_PARAMS = -32602;
const MODERN = '2026-07-28';
const INTERNAL_ERROR = -32603;
const MISSING_CLIENT_CAPABILITY = -32021;
const OWN_STATE = 'own-round-1';
const WRITE = { mutates: true, egress: false } as const;
const CONNECTION_CLOSED_MESSAGE = 'the audited call ended before it answered this request';
const REGISTRY_FULL_MESSAGE = 'this instance holds as many audited calls as it may';

/** What the tool under test did, across every server the factory built. */
class ToolState {
  invocations = 0;
  performed = 0;
  negotiated: boolean[] = [];
  readonly aborted: string[] = [];
  /** Resolves the handler's wait before its first operation, when `gate` is set. */
  gate: Promise<void> | undefined;
  /** Report progress before each operation, when the request asked for it. */
  progress = false;
  /** Open with one input round of the tool's own (`requestState` only) before any operation. */
  ownRound = false;
  /** The `requestState` each invocation was served with. */
  readonly states: (string | undefined)[] = [];
  /** How long an operation lasts once the host accepted it. */
  operationMs = 0;
  /** Go on to the next operation when one is aborted, rather than failing the call. */
  continueAfterAbort = false;
  aborts = 0;
  /** Run the operations concurrently, the first holding its accepted operation until `hold` resolves. */
  hold: Promise<void> | undefined;
  /** Resolves once the first operation was accepted and holds. */
  holding: Promise<void> = Promise.resolve();
  #held: () => void = () => {};
  /** Open with an input round that asks for `roots/list`, which the host's request does not declare. */
  askRoots = false;
  factoryCalls = 0;
  /** The factory throws on its call with this ordinal. */
  failFactoryAt: number | undefined;
  /** The client id of the authentication information the handler saw before each operation and at its end. */
  readonly clients: (string | undefined)[] = [];

  holdFirst(): () => void {
    let release: () => void = () => {};
    this.hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.holding = new Promise<void>((resolve) => {
      this.#held = resolve;
    });
    return release;
  }

  held(): void {
    this.#held();
  }
  readonly fallback = new AuditHost('tool-local', CAPABILITY, { clock: new MonotonicClock() });

  constructor(readonly operations = 3) {}
}

/**
 * A tool whose one tool mirrors its `region` argument into `Mcp-Param-Region` (`x-mcp-header`), and
 * performs `operations` audited reads one after another, so that each is a round of its own.
 */
function toolFactory(state: ToolState): AuditedServerFactory {
  return (audit) => {
    state.factoryCalls += 1;
    if (state.factoryCalls === state.failFactoryAt) {
      throw new Error('the factory failed');
    }
    const server = new McpServer({ name: 'audited-tool', version: '0.0.0' });
    server.registerTool(
      TOOL_NAME,
      {
        description: 'read',
        inputSchema: fromJsonSchema<{ region: string }>(REGION_SCHEMA),
      },
      async (_args, ctx) => {
        state.invocations += 1;
        const call = audit.call(ctx.mcpReq.id);
        const requestState = ctx.mcpReq.requestState<string>();
        state.states.push(requestState);
        if (state.askRoots) {
          return inputRequired({ inputRequests: { roots: inputRequired.listRoots() } });
        }
        if (state.ownRound && requestState === undefined) {
          return inputRequired({ requestState: OWN_STATE });
        }
        const negotiation = call.negotiate(CAPABILITY);
        state.negotiated.push(negotiation.negotiated);
        const chosen = transportFor(negotiation, {
          negotiated: call,
          fallback: new InProcessTransport(state.fallback),
        });
        if (chosen !== call) {
          state.fallback.openSession(call.sessionId);
        }
        ctx.mcpReq.signal.addEventListener('abort', () => state.aborted.push(call.sessionId));
        await state.gate;
        const session = new AmcpSession(chosen, call.sessionId);
        if (state.hold !== undefined) {
          const hold = state.hold;
          const first = (async () => {
            await using action = await session.action('db.write', { kind: 'table', ref: 'held' }, WRITE);
            state.held();
            await hold;
            state.performed += 1;
            action.succeeded();
          })();
          await state.holding;
          const second = (async () => {
            await using action = await session.action('db.write', { kind: 'table', ref: 'second' }, WRITE);
            state.performed += 1;
            action.succeeded();
          })();
          await Promise.all([first, second]);
          return { content: [{ type: 'text', text: 'held' }] };
        }
        for (let n = 0; n < state.operations; n += 1) {
          state.clients.push(authInfoOf(call)?.clientId);
          const progressToken = ctx.mcpReq._meta?.progressToken;
          if (state.progress && progressToken !== undefined) {
            await ctx.mcpReq.notify({
              method: 'notifications/progress',
              params: { progressToken, progress: n, total: state.operations },
            });
          }
          try {
            await using action = await session.action(
              'db.read',
              { kind: 'table', ref: `customers_${n}` },
              { mutates: false, egress: false },
            );
            state.performed += 1;
            if (state.operationMs > 0) {
              await new Promise((resolve) => setTimeout(resolve, state.operationMs));
            }
            action.succeeded();
          } catch (error) {
            if (!state.continueAfterAbort || !(error instanceof AmcpAbortedError)) {
              throw error;
            }
            state.aborts += 1;
          }
        }
        state.clients.push(authInfoOf(call)?.clientId);
        if (chosen !== call) {
          await state.fallback.closeSession(call.sessionId);
        }
        return { content: [{ type: 'text', text: `read ${state.operations} tables` }] };
      },
    );
    return server;
  };
}

interface Listening {
  readonly url: URL;
  readonly close: () => Promise<void>;
}

const open: Listening[] = [];
const handlers: AuditableMcpHandler[] = [];

afterEach(async () => {
  await Promise.all(open.splice(0).map((server) => server.close()));
  await Promise.all(handlers.splice(0).map((handler) => handler.close()));
});

async function listen(handler: FetchHandler): Promise<Listening> {
  const server: HttpServer = createServer(toNodeListener(handler));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the test server has no port');
  }
  const listening = {
    url: new URL(`http://127.0.0.1:${address.port}/mcp`),
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
  open.push(listening);
  return listening;
}

function entry(state: ToolState, options: Partial<AuditableMcpHandlerOptions> = {}): AuditableMcpHandler {
  const handler = createAuditableMcpHandler(toolFactory(state), { declares: CAPABILITY, ...options });
  handlers.push(handler);
  return handler;
}

/** One POST as a handler saw it, and the response it gave. */
interface Seen {
  readonly to: string;
  readonly headers: Headers;
  readonly body: unknown;
  response?: unknown;
  contentType?: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function paramsOf(body: unknown): Record<string, unknown> {
  return isRecord(body) && isRecord(body.params) ? body.params : {};
}

function sessionOf(body: unknown): string | undefined {
  const meta = paramsOf(body)._meta;
  const carried = isRecord(meta) ? meta[EXTENSION_ID] : undefined;
  return isRecord(carried) && typeof carried.session_id === 'string' ? carried.session_id : undefined;
}

function stateOf(value: unknown): string | undefined {
  const result = isRecord(value) && isRecord(value.result) ? value.result : undefined;
  return typeof result?.requestState === 'string' ? result.requestState : undefined;
}

function errorOf(value: unknown): { code: unknown; message: unknown } | undefined {
  return isRecord(value) && isRecord(value.error)
    ? { code: value.error.code, message: value.error.message }
    : undefined;
}

async function readJson(source: Request | Response): Promise<unknown> {
  const text = await source.text();
  if (text.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * A handler in front of `route`'s choice among `targets`, recording each POST and its JSON response. It
 * stands for whatever sits between a client and the instances: a load balancer, or none.
 */
function front(
  targets: Record<string, FetchHandler>,
  route: (seen: Seen) => string,
  log: Seen[],
  onResponse?: (seen: Seen) => Promise<void>,
): FetchHandler {
  return {
    fetch: async (request) => {
      if (request.method !== 'POST') {
        const first = Object.values(targets)[0];
        if (first === undefined) {
          throw new Error('no targets');
        }
        return first.fetch(request);
      }
      const partial = { headers: new Headers(request.headers), body: await readJson(request.clone()) };
      const to = route({ ...partial, to: '' });
      const seen: Seen = { ...partial, to };
      log.push(seen);
      const target = targets[to];
      if (target === undefined) {
        throw new Error(`no target ${to}`);
      }
      const response = await target.fetch(request);
      seen.contentType = response.headers.get('content-type');
      if (response.headers.get('content-type')?.includes('application/json') === true) {
        seen.response = await readJson(response.clone());
        await onResponse?.(seen);
      }
      return response;
    },
  };
}

function toolCalls(log: Seen[]): Seen[] {
  return log.filter((seen) => isRecord(seen.body) && seen.body.method === 'tools/call');
}

async function host(
  url: URL,
  headers: Record<string, string> = {},
): Promise<{ client: Client; audit: AuditHost; close: () => Promise<void> }> {
  const audit = new AuditHost('tenant-a', CAPABILITY, { clock: new MonotonicClock() });
  const receiver = new McpAuditReceiver(new StreamableHTTPClientTransport(url, { requestInit: { headers } }), audit);
  const client = new Client({ name: 'host', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
  await client.connect(receiver);
  await client.listTools();
  return { client, audit, close: () => client.close() };
}

function callTool(client: Client): ReturnType<Client['callTool']> {
  return client.callTool({ name: TOOL_NAME, arguments: { region: REGION } });
}

function textOf(result: Awaited<ReturnType<Client['callTool']>>): string {
  const content: unknown[] = Array.isArray(result.content) ? result.content : [];
  return content.map((block) => (isRecord(block) && typeof block.text === 'string' ? block.text : '')).join('');
}

async function post(
  url: URL,
  body: unknown,
  headers: Headers,
  signal?: AbortSignal,
): Promise<{ status: number; json: unknown }> {
  const sent = new Headers(headers);
  for (const name of ['content-length', 'host', 'connection']) {
    sent.delete(name);
  }
  const response = await fetch(url, {
    method: 'POST',
    headers: sent,
    body: JSON.stringify(body),
    ...(signal === undefined ? {} : { signal }),
  });
  return { status: response.status, json: await readJson(response) };
}

function withHeader(headers: Headers, name: string, value: string | undefined): Headers {
  const copy = new Headers(headers);
  if (value === undefined) {
    copy.delete(name);
  } else {
    copy.set(name, value);
  }
  return copy;
}

function withSession(body: unknown, sessionId: string | undefined, id: number): unknown {
  const params = paramsOf(body);
  const meta = isRecord(params._meta) ? { ...params._meta } : {};
  if (sessionId === undefined) {
    delete meta[EXTENSION_ID];
  } else {
    meta[EXTENSION_ID] = { session_id: sessionId };
  }
  const { requestState: _state, ...rest } = params;
  return { ...(isRecord(body) ? body : {}), id, params: { ...rest, _meta: meta } };
}

/** Run one audited call through `url` and return what the front recorded. */
async function recordedCall(state: ToolState): Promise<{ log: Seen[]; url: URL; handler: AuditableMcpHandler }> {
  const handler = entry(state);
  const log: Seen[] = [];
  const { url } = await listen(front({ a: handler }, () => 'a', log));
  const { client, close } = await host(url);
  await callTool(client);
  await close();
  return { log, url, handler };
}

describe('the HTTP entry serves an audited call over real Streamable HTTP (§6.4)', () => {
  it('carries a call of several rounds to its end, and the ledger verifies', async () => {
    const state = new ToolState(3);
    const handler = entry(state);
    const log: Seen[] = [];
    const { url } = await listen(front({ a: handler }, () => 'a', log));
    const { client, audit, close } = await host(url);
    const result = await callTool(client);
    await close();

    expect(result.isError).not.toBe(true);
    expect(textOf(result)).toBe('read 3 tables');
    expect(state.performed).toBe(3);
    expect(state.invocations).toBe(1);
    expect(state.negotiated).toEqual([true]);
    const records = audit.records();
    expect(records).toHaveLength(6);
    expect(verifyLedger(records, audit.digest()).ok).toBe(true);
    expect(audit.anomalies()).toEqual([]);
    const calls = toolCalls(log);
    // The opening request, then one retry per round.
    expect(calls).toHaveLength(4);
    const tokens = calls.map((seen) => stateOf(seen.response)).filter((token) => token !== undefined);
    expect(tokens).toHaveLength(3);
    for (const token of tokens) {
      expect(token.startsWith(ROUND_TOKEN_PREFIX)).toBe(true);
      expect(instanceOfToken(token)).toBe(handler.instance);
    }
  });

  it('puts the affinity header, Mcp-Method, Mcp-Name and Mcp-Param-* on the opening request and every retry', async () => {
    const { log } = await recordedCall(new ToolState(3));
    const calls = toolCalls(log);
    expect(calls.length).toBeGreaterThan(1);
    const sessionId = sessionOf(calls[0]?.body);
    expect(sessionId).toBeDefined();
    for (const seen of calls) {
      expect(sessionOf(seen.body)).toBe(sessionId);
      expect(seen.headers.get(AFFINITY_HEADER)).toBe(sessionId);
      expect(seen.headers.get('mcp-method')).toBe('tools/call');
      expect(seen.headers.get('mcp-name')).toBe(TOOL_NAME);
      expect(seen.headers.get(REGION_HEADER)).toBe(REGION);
      expect(seen.headers.get('mcp-protocol-version')).toBe(MODERN);
    }
    // Requests that are not part of an audited call carry no affinity header.
    for (const seen of log.filter((s) => !calls.includes(s))) {
      expect(seen.headers.get(AFFINITY_HEADER)).toBeNull();
    }
  });

  it('streams what the tool reports during a round as SSE ahead of the round, under the default response mode', async () => {
    const state = new ToolState(3);
    state.progress = true;
    const log: Seen[] = [];
    const { url } = await listen(front({ a: entry(state) }, () => 'a', log));
    const { client, audit, close } = await host(url);
    const progress: number[] = [];
    const result = await client.callTool(
      { name: TOOL_NAME, arguments: { region: REGION } },
      { onprogress: (update) => progress.push(update.progress) },
    );
    await close();

    expect(result.isError).not.toBe(true);
    expect(progress).toEqual([0, 1, 2]);
    expect(state.performed).toBe(3);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
    expect(toolCalls(log).some((seen) => seen.contentType?.startsWith('text/event-stream') === true)).toBe(true);
  });

  it('ends the call at the host when its client cancels it while a round is being decided (§6.3)', async () => {
    const state = new ToolState(2);
    const log: Seen[] = [];
    const { url } = await listen(front({ a: entry(state) }, () => 'a', log));
    const audit = new AuditHost('tenant-a', CAPABILITY, { clock: new MonotonicClock() });
    let entered: () => void = () => {};
    const deciding = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const closed: string[] = [];
    const endpoint: AuditEndpoint = {
      capability: audit.capability,
      openSession: (sessionId) => audit.openSession(sessionId),
      closeSession: async (sessionId) => {
        closed.push(sessionId);
        await audit.closeSession(sessionId);
      },
      handleAttempt: async (event, sessionId, deadline) => {
        entered();
        await gate;
        return audit.handleAttempt(event, sessionId, deadline);
      },
      handleOutcome: (event, sessionId) => audit.handleOutcome(event, sessionId),
    };
    const client = new Client({ name: 'host', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(new McpAuditReceiver(new StreamableHTTPClientTransport(url), endpoint));
    await client.listTools();
    const controller = new AbortController();
    const pending = client
      .callTool({ name: TOOL_NAME, arguments: { region: REGION } }, { signal: controller.signal })
      .catch((error: unknown) => error);
    await deciding;
    controller.abort();
    release();
    expect(await pending).toBeInstanceOf(Error);
    await expect.poll(() => closed).toHaveLength(1);
    await client.close();
    expect(toolCalls(log)).toHaveLength(1);
    expect(state.performed).toBe(0);
  });

  it('serves an unaudited call through the official handler, where the tool degrades (§6.2)', async () => {
    const state = new ToolState(2);
    const { url } = await listen(entry(state));
    const client = new Client({ name: 'plain', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(new StreamableHTTPClientTransport(url));
    expect(capabilityOf(client.getServerCapabilities())).toEqual(CAPABILITY);
    const result = await callTool(client);
    await client.close();
    expect(result.isError).not.toBe(true);
    expect(state.negotiated).toEqual([false]);
    expect(state.performed).toBe(2);
    expect(state.fallback.records()).toHaveLength(4);
  });
});

describe('the HTTP entry checks what it takes over', () => {
  it('refuses a replayed round token and performs nothing (§6.4 at most once)', async () => {
    const state = new ToolState(2);
    const { log, url } = await recordedCall(state);
    const calls = toolCalls(log);
    const retry = calls[1];
    expect(retry).toBeDefined();
    if (retry === undefined) {
      return;
    }
    const replay = await post(url, retry.body, retry.headers);
    expect(replay.status).toBe(200);
    expect(errorOf(replay.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    expect(state.performed).toBe(2);
    expect(state.invocations).toBe(1);
  });

  it('refuses with 400 and -32020 an affinity header that is absent, different, or without a session', async () => {
    const state = new ToolState(1);
    const { log, url } = await recordedCall(state);
    const opening = toolCalls(log)[0];
    expect(opening).toBeDefined();
    if (opening === undefined) {
      return;
    }
    const fresh = globalThis.crypto.randomUUID();
    const cases: { body: unknown; header: string | undefined }[] = [
      { body: withSession(opening.body, fresh, 71), header: undefined },
      { body: withSession(opening.body, fresh, 72), header: globalThis.crypto.randomUUID() },
      { body: withSession(opening.body, undefined, 73), header: fresh },
    ];
    for (const { body, header } of cases) {
      const answer = await post(url, body, withHeader(opening.headers, AFFINITY_HEADER, header));
      expect(answer.status).toBe(400);
      expect(errorOf(answer.json)?.code).toBe(HEADER_MISMATCH);
      expect(isRecord(answer.json) ? answer.json.id : undefined).toBe(isRecord(body) ? body.id : undefined);
    }
    expect(state.invocations).toBe(1);
  });

  it('runs the official validation on a taken-over request: no Mcp-Param-*, no Mcp-Method, nothing runs', async () => {
    const state = new ToolState(1);
    const { log, url } = await recordedCall(state);
    const opening = toolCalls(log)[0];
    expect(opening).toBeDefined();
    if (opening === undefined) {
      return;
    }
    for (const [name, id] of [
      [REGION_HEADER, 81],
      ['mcp-method', 82],
    ] as const) {
      const fresh = globalThis.crypto.randomUUID();
      const headers = withHeader(withHeader(opening.headers, AFFINITY_HEADER, fresh), name, undefined);
      const answer = await post(url, withSession(opening.body, fresh, id), headers);
      expect(answer.status).toBe(400);
      expect(errorOf(answer.json)?.code).toBeTypeOf('number');
    }
    expect(state.invocations).toBe(1);
  });

  it('refuses a retry that another principal presents, and the opener still concludes the call (§6.4)', async () => {
    const state = new ToolState(2);
    const handler = entry(state, {
      principalOf: (request) => request.headers.get(PRINCIPAL_HEADER) ?? undefined,
    });
    const log: Seen[] = [];
    const hijacks: unknown[] = [];
    let url: URL | undefined;
    const listening = await listen(
      front(
        { a: handler },
        () => 'a',
        log,
        async (seen) => {
          const token = stateOf(seen.response);
          if (token !== undefined && hijacks.length === 0 && url !== undefined) {
            const forged = {
              ...(isRecord(seen.body) ? seen.body : {}),
              id: 99,
              params: { ...paramsOf(seen.body), requestState: token },
            };
            hijacks.push((await post(url, forged, withHeader(seen.headers, PRINCIPAL_HEADER, 'mallory'))).json);
          }
        },
      ),
    );
    url = listening.url;
    const { client, audit, close } = await host(url, { [PRINCIPAL_HEADER]: 'alice' });
    const result = await callTool(client);
    await close();

    expect(hijacks).toHaveLength(1);
    expect(errorOf(hijacks[0])?.code).toBe(INVALID_PARAMS);
    expect(String(errorOf(hijacks[0])?.message)).toContain('another principal');
    expect(result.isError).not.toBe(true);
    expect(state.performed).toBe(2);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
  });

  it('cancels the call when the HTTP request that carries it goes away', async () => {
    const state = new ToolState(1);
    const { log, url } = await recordedCall(state);
    const opening = toolCalls(log)[0];
    expect(opening).toBeDefined();
    if (opening === undefined) {
      return;
    }
    let release: () => void = () => {};
    state.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fresh = globalThis.crypto.randomUUID();
    const controller = new AbortController();
    const pending = post(
      url,
      withSession(opening.body, fresh, 91),
      withHeader(opening.headers, AFFINITY_HEADER, fresh),
      controller.signal,
    ).catch((error: unknown) => error);
    await expect.poll(() => state.invocations).toBe(2);
    controller.abort();
    await pending;
    await expect.poll(() => state.aborted).toContain(fresh);
    release();
    expect(state.performed).toBe(1);
  });

  it('closes an idle call, after which its retry is refused', async () => {
    const state = new ToolState(1);
    const handler = entry(state, { idleTimeoutMs: 20 });
    const log: Seen[] = [];
    const { url } = await listen(front({ a: handler }, () => 'a', log));
    const template = await recordedCall(new ToolState(1));
    const opening = toolCalls(template.log)[0];
    expect(opening).toBeDefined();
    if (opening === undefined) {
      return;
    }
    const fresh = globalThis.crypto.randomUUID();
    const headers = withHeader(opening.headers, AFFINITY_HEADER, fresh);
    const first = await post(url, withSession(opening.body, fresh, 101), headers);
    const token = stateOf(first.json);
    expect(token).toBeDefined();
    await expect.poll(() => state.aborted, { timeout: 2_000 }).toContain(fresh);
    const next = withSession(opening.body, fresh, 102);
    const retry = { ...(isRecord(next) ? next : {}), params: { ...paramsOf(next), requestState: token } };
    const answer = await post(url, retry, headers);
    expect(errorOf(answer.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    expect(state.performed).toBe(0);
  });
});

describe('the registry of held calls', () => {
  it('closes the least recently used idle call beyond maxHeldCalls, whose retry is then refused', async () => {
    const state = new ToolState(1);
    const { url } = await listen(entry(state, { maxHeldCalls: 1 }));
    const template = await recordedCall(new ToolState(1));
    const opening = toolCalls(template.log)[0];
    expect(opening).toBeDefined();
    if (opening === undefined) {
      return;
    }
    const sessions = [globalThis.crypto.randomUUID(), globalThis.crypto.randomUUID()];
    const tokens: (string | undefined)[] = [];
    for (const [n, sessionId] of sessions.entries()) {
      const answer = await post(
        url,
        withSession(opening.body, sessionId, 111 + n),
        withHeader(opening.headers, AFFINITY_HEADER, sessionId),
      );
      tokens.push(stateOf(answer.json));
    }
    expect(tokens.every((token) => token !== undefined)).toBe(true);
    await expect.poll(() => state.aborted).toEqual([sessions[0]]);
    const evicted = withSession(opening.body, sessions[0], 121);
    const retry = { ...(isRecord(evicted) ? evicted : {}), params: { ...paramsOf(evicted), requestState: tokens[0] } };
    const answer = await post(url, retry, withHeader(opening.headers, AFFINITY_HEADER, sessions[0]));
    expect(errorOf(answer.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    expect(state.performed).toBe(0);
  });
});

describe('a deployment of several instances (§6.4 round affinity)', () => {
  /** Opening requests to `a`, every retry to `b`: the routing that loses affinity. */
  const misroute = (seen: Seen): string => (paramsOf(seen.body).requestState === undefined ? 'a' : 'b');

  it('forwards a retry sent to the wrong instance to its owner, and the tool runs once', async () => {
    const state = new ToolState(3);
    const registry = new Map<string, URL>();
    const forward = fetchForwarder({ resolve: (instance) => registry.get(instance) });
    const a = entry(state, { instance: 'instance-a', forward });
    const b = entry(state, { instance: 'instance-b', forward });
    const ownerLog: Seen[] = [];
    registry.set('instance-a', (await listen(front({ a }, () => 'a', ownerLog))).url);
    registry.set('instance-b', (await listen(b)).url);
    const log: Seen[] = [];
    const { url } = await listen(front({ a, b }, misroute, log));
    const { client, audit, close } = await host(url);
    const result = await callTool(client);
    await close();

    expect(result.isError).not.toBe(true);
    expect(state.invocations).toBe(1);
    expect(state.performed).toBe(3);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
    expect(toolCalls(log).filter((seen) => seen.to === 'b')).toHaveLength(3);
    const forwarded = toolCalls(ownerLog);
    expect(forwarded).toHaveLength(3);
    for (const seen of forwarded) {
      expect(seen.headers.get(FORWARDED_HEADER)).toBe('1');
      expect(seen.headers.get(REGION_HEADER)).toBe(REGION);
    }
  });

  it('without a forwarder refuses a misrouted retry, and the tool performs nothing', async () => {
    const state = new ToolState(2);
    const a = entry(state, { instance: 'instance-a' });
    const b = entry(state, { instance: 'instance-b' });
    const log: Seen[] = [];
    const { url } = await listen(front({ a, b }, misroute, log));
    const { client, close } = await host(url);
    await expect(callTool(client)).rejects.toThrow(NO_OPEN_ROUND_MESSAGE);
    await close();
    expect(state.invocations).toBe(1);
    expect(state.performed).toBe(0);
  });

  it('keeps every round of a call on one instance behind a router that hashes on Auditable-Mcp-Session', async () => {
    const state = new ToolState(2);
    const a = entry(state, { instance: 'instance-a' });
    const b = entry(state, { instance: 'instance-b' });
    const byHash = (seen: Seen): string => {
      const session = seen.headers.get(AFFINITY_HEADER);
      if (session === null) {
        return 'a';
      }
      let hash = 0;
      for (const char of session) {
        hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
      }
      return hash % 2 === 0 ? 'a' : 'b';
    };
    const log: Seen[] = [];
    const { url } = await listen(front({ a, b }, byHash, log));
    const { client, audit, close } = await host(url);
    const calls = 6;
    const results = await Promise.all(Array.from({ length: calls }, () => callTool(client)));
    await close();

    expect(results.every((result) => result.isError !== true)).toBe(true);
    expect(state.performed).toBe(calls * 2);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
    const instancesBySession = new Map<string, Set<string>>();
    for (const seen of toolCalls(log)) {
      const session = sessionOf(seen.body) ?? '';
      instancesBySession.set(session, (instancesBySession.get(session) ?? new Set()).add(seen.to));
    }
    expect(instancesBySession.size).toBe(calls);
    for (const instances of instancesBySession.values()) {
      expect(instances.size).toBe(1);
    }
  });

  it('never forwards a request that carries the forward marker, so a forward cannot loop', async () => {
    const state = new ToolState(1);
    const registry = new Map<string, URL>();
    let resolved = 0;
    const forward = fetchForwarder({
      resolve: (instance) => {
        resolved += 1;
        return registry.get(instance);
      },
    });
    const b = entry(state, { instance: 'instance-b', forward });
    const log: Seen[] = [];
    const { url } = await listen(front({ b }, () => 'b', log));
    // A misconfigured registry that sends instance-c to instance-b itself.
    registry.set('instance-c', url);
    const template = await recordedCall(new ToolState(1));
    const retry = toolCalls(template.log)[1];
    expect(retry).toBeDefined();
    if (retry === undefined) {
      return;
    }
    const forged = `${ROUND_TOKEN_PREFIX}instance-c.${'A'.repeat(43)}`;
    const body = {
      ...(isRecord(retry.body) ? retry.body : {}),
      params: { ...paramsOf(retry.body), requestState: forged },
    };
    const answer = await post(url, body, retry.headers);
    expect(errorOf(answer.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    // The one forward reached instance-b again, marked, and went no further.
    expect(toolCalls(log)).toHaveLength(2);
    expect(toolCalls(log)[1]?.headers.get(FORWARDED_HEADER)).toBe('1');
    expect(resolved).toBe(1);
    expect(state.invocations).toBe(0);
  });

  it('refuses a retry whose token names an instance the deployment does not know, contacting nothing', async () => {
    const state = new ToolState(1);
    const asked: string[] = [];
    let sent = 0;
    const forward = fetchForwarder({
      resolve: (instance) => {
        asked.push(instance);
        return undefined;
      },
      fetch: async () => {
        sent += 1;
        return new Response(null, { status: 500 });
      },
    });
    const b = entry(state, { instance: 'instance-b', forward });
    const { url } = await listen(b);
    const template = await recordedCall(new ToolState(1));
    const retry = toolCalls(template.log)[1];
    expect(retry).toBeDefined();
    if (retry === undefined) {
      return;
    }
    for (const requestState of [
      `${ROUND_TOKEN_PREFIX}nowhere.${'B'.repeat(43)}`,
      `${ROUND_TOKEN_PREFIX}evil.example.com:80/.${'B'.repeat(43)}`,
    ]) {
      const body = { ...(isRecord(retry.body) ? retry.body : {}), params: { ...paramsOf(retry.body), requestState } };
      const answer = await post(url, body, retry.headers);
      expect(errorOf(answer.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    }
    // Only the well-formed name reached the resolver; nothing was sent anywhere.
    expect(asked).toEqual(['nowhere']);
    expect(sent).toBe(0);
    expect(state.invocations).toBe(0);
  });
});

/** A recorded opening request and the retry that followed it, to post by hand. */
async function recordedRequests(): Promise<{ opening: Seen; retry: Seen }> {
  const { log } = await recordedCall(new ToolState(1));
  const [opening, retry] = toolCalls(log);
  if (opening === undefined || retry === undefined) {
    throw new Error('the recorded call has no retry');
  }
  return { opening, retry };
}

/** Post an opening request of a fresh session to `url`, built from a recorded one. */
async function openFresh(
  url: URL,
  opening: Seen,
  id: number,
  sessionId: string = globalThis.crypto.randomUUID(),
): Promise<{ status: number; json: unknown; sessionId: string }> {
  const answer = await post(
    url,
    withSession(opening.body, sessionId, id),
    withHeader(opening.headers, AFFINITY_HEADER, sessionId),
  );
  return { ...answer, sessionId };
}

function withState(body: unknown, requestState: string | undefined): unknown {
  const params = paramsOf(body);
  const { requestState: _state, ...rest } = params;
  return { ...(isRecord(body) ? body : {}), params: requestState === undefined ? rest : { ...rest, requestState } };
}

/** An endpoint in front of `audit` whose decision on the attempt numbered `gated` (from 1) waits for `gate`. */
function gatedEndpoint(
  audit: AuditHost,
  gated: number,
  gate: Promise<void>,
): { endpoint: AuditEndpoint; reached: Promise<void> } {
  let attempts = 0;
  let reach: () => void = () => {};
  const reached = new Promise<void>((resolve) => {
    reach = resolve;
  });
  const endpoint: AuditEndpoint = {
    capability: audit.capability,
    openSession: (sessionId) => audit.openSession(sessionId),
    closeSession: (sessionId) => audit.closeSession(sessionId),
    handleAttempt: async (event, sessionId, deadline) => {
      attempts += 1;
      if (attempts === gated) {
        reach();
        await gate;
      }
      return audit.handleAttempt(event, sessionId, deadline);
    },
    handleOutcome: (event, sessionId) => audit.handleOutcome(event, sessionId),
  };
  return { endpoint, reached };
}

describe('review fixes', () => {
  it('F1: does not evict a held call whose accepted operation is under way, and refuses the new call instead', async () => {
    const state = new ToolState(2);
    const release = state.holdFirst();
    const handler = entry(state, { maxHeldCalls: 1 });
    const { url } = await listen(handler);
    const audit = new AuditHost('tenant-a', CAPABILITY, { clock: new MonotonicClock() });
    let decide: () => void = () => {};
    const { endpoint, reached } = gatedEndpoint(
      audit,
      2,
      new Promise<void>((resolve) => {
        decide = resolve;
      }),
    );
    const client = new Client({ name: 'host', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(new McpAuditReceiver(new StreamableHTTPClientTransport(url), endpoint));
    await client.listTools();
    const call = callTool(client);
    // The first operation is accepted and under way; the second attempt's round is out, and the host is
    // still deciding it, so no request of the call is in flight.
    await reached;
    const { opening } = await recordedRequests();
    const refused = await openFresh(url, opening, 131);
    expect(errorOf(refused.json)).toEqual({ code: INTERNAL_ERROR, message: REGISTRY_FULL_MESSAGE });
    decide();
    release();
    const result = await call;
    await client.close();
    expect(result.isError).not.toBe(true);
    expect(state.performed).toBe(2);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
  });

  it('F2: answers a forward cut short after the owner received it as an unknown outcome, not a refusal', async () => {
    const state = new ToolState(1);
    state.operationMs = 600;
    const registry = new Map<string, URL>();
    const forward = fetchForwarder({
      resolve: (instance) => registry.get(instance),
      fetch: (input, init) =>
        fetch(input, {
          ...init,
          signal: AbortSignal.any([init.signal ?? new AbortController().signal, AbortSignal.timeout(200)]),
        }),
    });
    const a = entry(state, { instance: 'instance-a', forward });
    const b = entry(state, { instance: 'instance-b', forward });
    registry.set('instance-a', (await listen(a)).url);
    const { url } = await listen(
      front({ a, b }, (seen) => (paramsOf(seen.body).requestState === undefined ? 'a' : 'b'), []),
    );
    const { client, close } = await host(url);
    await expect(callTool(client)).rejects.toThrow(FORWARD_UNKNOWN_MESSAGE);
    await close();
    await expect.poll(() => state.performed).toBe(1);
  });

  it('F2: refuses a retry whose forward never connected, and answers a forwarder that throws in-band', async () => {
    const dead = await listen(entry(new ToolState(1)));
    await dead.close();
    const { retry } = await recordedRequests();
    const forged = withState(retry.body, `${ROUND_TOKEN_PREFIX}instance-a.${'C'.repeat(43)}`);
    const cases: { forward: AuditableMcpHandlerOptions['forward']; expected: { code: number; message: string } }[] = [
      {
        forward: fetchForwarder({ resolve: () => dead.url }),
        expected: { code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE },
      },
      {
        forward: fetchForwarder({
          resolve: () => {
            throw new Error('the registry is down');
          },
        }),
        expected: { code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE },
      },
      {
        forward: async () => {
          throw new Error('a custom forwarder failed');
        },
        expected: { code: INTERNAL_ERROR, message: FORWARD_UNKNOWN_MESSAGE },
      },
      {
        forward: fetchForwarder({
          resolve: () => new URL('http://127.0.0.1:1/mcp'),
          fetch: async () => new Response(null, { status: 307, headers: { location: 'http://169.254.169.254/' } }),
        }),
        expected: { code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE },
      },
    ];
    for (const [n, { forward, expected }] of cases.entries()) {
      const state = new ToolState(1);
      const { url } = await listen(
        entry(state, { instance: `instance-b${n}`, ...(forward === undefined ? {} : { forward }) }),
      );
      const answer = await post(url, forged, retry.headers);
      expect(answer.status).toBe(200);
      expect(errorOf(answer.json)).toEqual(expected);
      expect(state.invocations).toBe(0);
    }
  });

  it("F3: gives the tool's own round a token that names this instance, and the tool its own state back", async () => {
    const state = new ToolState(1);
    state.ownRound = true;
    const handler = entry(state, { instance: 'instance-a' });
    const log: Seen[] = [];
    const { url } = await listen(front({ a: handler }, () => 'a', log));
    const { client, audit, close } = await host(url);
    const result = await callTool(client);
    await close();
    expect(result.isError).not.toBe(true);
    const own = stateOf(toolCalls(log)[0]?.response);
    expect(own === undefined ? undefined : instanceOfToken(own)).toBe('instance-a');
    expect(state.states).toEqual([undefined, OWN_STATE]);
    expect(state.performed).toBe(1);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
  });

  it("F3: forwards the retry of the tool's own round to its owner, and refuses it without a forwarder", async () => {
    for (const forwarding of [true, false]) {
      const state = new ToolState(1);
      state.ownRound = true;
      const registry = new Map<string, URL>();
      const forward = fetchForwarder({ resolve: (instance) => registry.get(instance) });
      const a = entry(state, { instance: 'instance-a', ...(forwarding ? { forward } : {}) });
      const b = entry(state, { instance: 'instance-b', ...(forwarding ? { forward } : {}) });
      registry.set('instance-a', (await listen(a)).url);
      const { url } = await listen(
        front({ a, b }, (seen) => (paramsOf(seen.body).requestState === undefined ? 'a' : 'b'), []),
      );
      const { client, close } = await host(url);
      if (forwarding) {
        expect((await callTool(client)).isError).not.toBe(true);
        expect(state.performed).toBe(1);
      } else {
        await expect(callTool(client)).rejects.toThrow(NO_OPEN_ROUND_MESSAGE);
        expect(state.performed).toBe(0);
        expect(state.states).toEqual([undefined]);
      }
      await close();
    }
  });

  it('F3: never serves a request that carries a requestState as the first request of a session it does not hold', async () => {
    const state = new ToolState(1);
    const { url } = await listen(entry(state));
    const { opening } = await recordedRequests();
    const sessionId = globalThis.crypto.randomUUID();
    const answer = await post(
      url,
      withState(withSession(opening.body, sessionId, 141), 'a-state-this-instance-never-issued'),
      withHeader(opening.headers, AFFINITY_HEADER, sessionId),
    );
    expect(errorOf(answer.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    expect(state.invocations).toBe(0);
  });

  it('F4: refuses a second opening of a session it holds, which never reaches the held call', async () => {
    const state = new ToolState(1);
    const { url } = await listen(entry(state));
    const { opening } = await recordedRequests();
    const first = await openFresh(url, opening, 151);
    expect(stateOf(first.json)).toBeDefined();
    const again = await openFresh(url, opening, 152, first.sessionId);
    expect(errorOf(again.json)).toEqual({ code: INVALID_PARAMS, message: SESSION_OPEN_MESSAGE });
    expect(state.invocations).toBe(1);
  });

  it('F5: answers -32021 raised by the held server with HTTP 400, as the official validation answers it', async () => {
    const { opening } = await recordedRequests();
    const state = new ToolState(1);
    state.askRoots = true;
    const { url } = await listen(entry(state));
    const answer = await openFresh(url, opening, 161);
    expect(answer.status).toBe(400);
    expect(errorOf(answer.json)?.code).toBe(MISSING_CLIENT_CAPABILITY);
    expect(state.invocations).toBe(1);
  });

  it('F6: answers in-band when the factory fails for an audited request, whichever server it was building', async () => {
    const { opening } = await recordedRequests();
    // The first factory call builds the server the official handler validates with; the second, the held call's.
    for (const failAt of [1, 2]) {
      const state = new ToolState(1);
      state.failFactoryAt = failAt;
      const { url } = await listen(entry(state));
      const answer = await openFresh(url, opening, 171);
      expect(answer.status).toBe(200);
      expect(errorOf(answer.json)).toEqual({ code: INTERNAL_ERROR, message: CONNECTION_CLOSED_MESSAGE });
      expect(state.invocations).toBe(0);
    }
  });

  it('F7: lets the handler read the authentication of the request it is being served under now', async () => {
    const state = new ToolState(2);
    const handler = entry(state);
    let posts = 0;
    const { url } = await listen({
      fetch: (request) => {
        posts += 1;
        return handler.fetch(request, { authInfo: { token: `t-${posts}`, clientId: `post-${posts}`, scopes: [] } });
      },
    });
    const { client, close } = await host(url);
    const before = posts;
    expect((await callTool(client)).isError).not.toBe(true);
    await close();
    const first = before + 1;
    expect(state.clients).toEqual([`post-${first}`, `post-${first + 1}`, `post-${first + 2}`]);
  });

  it('F9: validates a misrouted retry before forwarding it, so a malformed one never leaves', async () => {
    const state = new ToolState(1);
    let forwarded = 0;
    const b = entry(state, {
      instance: 'instance-b',
      forward: async () => {
        forwarded += 1;
        return new Response(null, { status: 500 });
      },
    });
    const { url } = await listen(b);
    const { retry } = await recordedRequests();
    const forged = withState(retry.body, `${ROUND_TOKEN_PREFIX}instance-a.${'D'.repeat(43)}`);
    const answer = await post(url, forged, withHeader(retry.headers, REGION_HEADER, undefined));
    expect(answer.status).toBe(400);
    expect(errorOf(answer.json)?.code).toBe(HEADER_MISMATCH);
    expect(forwarded).toBe(0);
  });

  it('F9: serves the official path behind the seam, so an unaudited call reaches its call and the declaration goes out', async () => {
    const state = new ToolState(1);
    const { url } = await listen(entry(state));
    const client = new Client({ name: 'plain', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(new StreamableHTTPClientTransport(url));
    expect(capabilityOf(client.getServerCapabilities())).toEqual(CAPABILITY);
    // `audit.call(id)` throws for a request the seam did not see; the handler reaching negotiation proves it did.
    expect((await callTool(client)).isError).not.toBe(true);
    await client.close();
    expect(state.negotiated).toEqual([false]);
  });
});

const LATE_ACCEPT = {
  status: 'accept',
  seq: 0,
  record_hash: 'a'.repeat(64),
  host_ts: '2026-07-15T00:00:01.000Z',
  previous_hash: '0'.repeat(64),
};

/** The id of the first attempt a round's answer carries. */
function firstAttemptOf(answer: unknown): string | undefined {
  const result = isRecord(answer) && isRecord(answer.result) ? answer.result : undefined;
  const meta = result !== undefined && isRecord(result._meta) ? result._meta[EXTENSION_ID] : undefined;
  const events = isRecord(meta) && Array.isArray(meta.events) ? meta.events : [];
  const attempt: unknown = events.find((event) => isRecord(event) && event.outcome === 'attempted');
  return isRecord(attempt) && typeof attempt.id === 'string' ? attempt.id : undefined;
}

/** A retry of `token` built from a recorded opening, carrying `responses` under `sessionId`. */
function retryOf(
  opening: Seen,
  sessionId: string | undefined,
  token: string,
  id: number,
  responses?: unknown,
): unknown {
  const body = withSession(opening.body, sessionId, id);
  const params = paramsOf(body);
  const meta = isRecord(params._meta) ? { ...params._meta } : {};
  if (sessionId !== undefined && responses !== undefined) {
    meta[EXTENSION_ID] = { session_id: sessionId, responses };
  }
  return { ...(isRecord(body) ? body : {}), params: { ...params, _meta: meta, requestState: token } };
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe('second-round fixes: the held-call lifetime rule', () => {
  it('F13: never expires a running call, whose accepted operation goes on to its outcome', async () => {
    const state = new ToolState(2);
    const release = state.holdFirst();
    const { url } = await listen(entry(state, { idleTimeoutMs: 30 }));
    const audit = new AuditHost('tenant-a', CAPABILITY, { clock: new MonotonicClock() });
    let decide: () => void = () => {};
    const { endpoint, reached } = gatedEndpoint(
      audit,
      2,
      new Promise<void>((resolve) => {
        decide = resolve;
      }),
    );
    const client = new Client({ name: 'host', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(new McpAuditReceiver(new StreamableHTTPClientTransport(url), endpoint));
    await client.listTools();
    const call = callTool(client);
    await reached;
    // No request is in flight and the idle bound passes several times over while the operation runs.
    await sleep(200);
    decide();
    release();
    const result = await call;
    await client.close();
    expect(result.isError).not.toBe(true);
    expect(state.performed).toBe(2);
    expect(verifyLedger(audit.records(), audit.digest()).ok).toBe(true);
  });

  it('F13: never evicts an undelivered call, and still expires it after the idle bound', async () => {
    const state = new ToolState(1);
    const { url } = await listen(entry(state, { requestTimeoutMs: 50, idleTimeoutMs: 400, maxHeldCalls: 1 }));
    const { opening } = await recordedRequests();
    const first = await openFresh(url, opening, 181);
    const token = stateOf(first.json);
    expect(token).toBeDefined();
    // The attempt goes unanswered, the handler concludes while the round is out, and the call now holds
    // its outcome and final frame for the round's retry.
    await expect.poll(() => state.invocations).toBe(1);
    await sleep(150);
    const refused = await openFresh(url, opening, 182);
    expect(errorOf(refused.json)).toEqual({ code: INTERNAL_ERROR, message: REGISTRY_FULL_MESSAGE });
    await sleep(500);
    const late = await post(
      url,
      retryOf(opening, first.sessionId, token ?? '', 183),
      withHeader(opening.headers, AFFINITY_HEADER, first.sessionId),
    );
    expect(errorOf(late.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    const admitted = await openFresh(url, opening, 184);
    expect(stateOf(admitted.json)).toBeDefined();
    expect(state.performed).toBe(0);
  });

  it('F15: an accept that arrives after its attempt was answered unavailable does not make the call running', async () => {
    const state = new ToolState(2);
    state.continueAfterAbort = true;
    const { url } = await listen(entry(state, { requestTimeoutMs: 300, maxHeldCalls: 1 }));
    const { opening } = await recordedRequests();
    const first = await openFresh(url, opening, 191);
    const token = stateOf(first.json);
    const attempt = firstAttemptOf(first.json);
    expect(token !== undefined && attempt !== undefined).toBe(true);
    // The first attempt times out unanswered; the handler moves on and its second attempt waits for the
    // round that is still out.
    await expect.poll(() => state.aborts, { timeout: 2_000 }).toBe(1);
    const retried = await post(
      url,
      retryOf(opening, first.sessionId, token ?? '', 192, { [attempt ?? '']: LATE_ACCEPT }),
      withHeader(opening.headers, AFFINITY_HEADER, first.sessionId),
    );
    expect(stateOf(retried.json)).toBeDefined();
    // The handler now waits for the second round's retry with nothing under way, so the call gives way.
    const next = await openFresh(url, opening, 193);
    expect(errorOf(next.json)).toBeUndefined();
    expect(stateOf(next.json)).toBeDefined();
    expect(state.performed).toBe(0);
  });

  it("F14: refuses a retry of the tool's own round under no session or another, without consuming it", async () => {
    const state = new ToolState(1);
    state.ownRound = true;
    const { url } = await listen(entry(state));
    const { opening } = await recordedRequests();
    const first = await openFresh(url, opening, 201);
    const token = stateOf(first.json);
    expect(token === undefined ? undefined : instanceOfToken(token)).toBeDefined();
    const other = globalThis.crypto.randomUUID();
    for (const [sessionId, id] of [
      [undefined, 202],
      [other, 203],
    ] as const) {
      const answer = await post(
        url,
        retryOf(opening, sessionId, token ?? '', id),
        withHeader(opening.headers, AFFINITY_HEADER, sessionId),
      );
      expect(errorOf(answer.json)).toEqual({ code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE });
    }
    expect(state.states).toEqual([undefined]);
    const resumed = await post(
      url,
      retryOf(opening, first.sessionId, token ?? '', 204),
      withHeader(opening.headers, AFFINITY_HEADER, first.sessionId),
    );
    expect(errorOf(resumed.json)).toBeUndefined();
    expect(state.states).toEqual([undefined, OWN_STATE]);
  });

  it('F18: ends a forwarded SSE answer that breaks mid-stream with the unknown outcome, in-band', async () => {
    const state = new ToolState(1);
    const encoder = new TextEncoder();
    const b = entry(state, {
      instance: 'instance-b',
      forward: async () => {
        let sent = false;
        const body = new ReadableStream<Uint8Array>({
          pull(controller) {
            if (!sent) {
              sent = true;
              controller.enqueue(
                encoder.encode(
                  'event: message\r\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":0}}\r\n\r\n',
                ),
              );
              return;
            }
            controller.error(new Error('the owner went away'));
          },
        });
        return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
      },
    });
    const { url } = await listen(b);
    const { retry } = await recordedRequests();
    const forged = withState(retry.body, `${ROUND_TOKEN_PREFIX}instance-a.${'E'.repeat(43)}`);
    const answer = await post(url, forged, retry.headers);
    expect(answer.status).toBe(200);
    const text = String(answer.json);
    expect(text).toContain('notifications/progress');
    const last = text.trim().split('\r\n\r\n').at(-1) ?? '';
    const data: unknown = JSON.parse(last.replace(/^event: message\r\ndata: /, ''));
    expect(errorOf(data)).toEqual({ code: INTERNAL_ERROR, message: FORWARD_UNKNOWN_MESSAGE });
    expect(isRecord(data) ? data.id : undefined).toBe(isRecord(forged) ? forged.id : undefined);
  });
});
