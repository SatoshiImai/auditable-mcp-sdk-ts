/**
 * The tool's Streamable HTTP entry for MCP 2026-07-28 (§6.4), with round affinity.
 *
 * The official entry serves each POST statelessly: it builds a server from the factory, dispatches the one
 * request into it and discards it. The §6.4 seam instead keeps the tool's handler suspended between the
 * rounds of an audited call, so an audited call needs something that outlives one POST. This entry wraps
 * the official handler and takes over only the `tools/call` requests of audited calls:
 *
 * - one whose `_meta` carries this extension's `session_id` and no `requestState` - the request that opens
 *   an audited call; and
 * - a retry: one whose `requestState` is a round token of this entry (`amcp.`), or any `requestState` on a
 *   request that carries a `session_id`.
 *
 * Everything else - other methods, unaudited calls, 2025-era traffic - goes to the official handler
 * untouched, served by a server from the same factory behind a seam of its own, so an unaudited call is
 * negotiated (and refused a send) exactly as it is on any other transport (§6.2).
 *
 * An audited call gets a connection of its own in memory: a stream pair with the tool's server from the
 * factory on one end behind the existing seam, held in this entry's registry by `session_id` and by the
 * round tokens it has issued. Each POST of the call is written into that connection and answered with
 * what the connection answers on its id. The connection closes when the call concludes, when the HTTP
 * request that carries it is cancelled, or when it has been idle for `idleTimeoutMs`.
 *
 * Every round of an audited call is answered with a `requestState` that names this instance: the seam's
 * own tokens do, and a `requestState` the tool returns for one of its own input rounds is replaced here by
 * a token of the same form, and given back to the tool when the retry arrives. So a retry of any round
 * routes, and is forwarded, the same way (§6.4).
 *
 * A taken-over request passes the official handler's own validation first - `MCP-Protocol-Version`,
 * `Mcp-Method`, `Mcp-Name`, each `Mcp-Param-*` against the tool's `x-mcp-header` declarations, client
 * capabilities, scope challenges, content type - because it is dispatched through that handler into a
 * server whose `tools/call` handler serves it from the held connection, or forwards it. The response mode
 * (JSON, or SSE when the tool emits a notification before its result) is therefore the official handler's
 * `responseMode`, and a refusal or a handler's error is answered in-band with HTTP 200, as the official
 * handler answers a handler's error - except `-32020` and `-32021`, which are HTTP 400 wherever they
 * arise. Only the checks the official handler does not make are made here: the `Auditable-Mcp-Session`
 * header against the body (§6.4), and, when configured, `Origin` and `Host` for every request.
 *
 * A retry whose round this instance does not hold is forwarded when `forward` is given, the token names
 * another instance, and the request was not itself forwarded; otherwise it is refused as a replay is,
 * performing nothing (§6.4, §10.11).
 */

import {
  type AuthInfo,
  type CallToolResult,
  createMcpHandler,
  DEFAULT_MAX_REQUEST_BODY_SIZE,
  hostHeaderValidationResponse,
  type InputRequiredResult,
  isCallToolResult,
  isInputRequiredResult,
  isJsonContentType,
  type McpHandlerRequestOptions,
  type McpRequestContext,
  McpServer,
  originValidationResponse,
  type PerRequestResponseMode,
  PROTOCOL_VERSION_META_KEY,
  ProtocolError,
  readRequestBody,
  Server,
  type ServerContext,
  type Transport,
} from '@modelcontextprotocol/server';
import { type StdioServerHandle, serveStdio } from '@modelcontextprotocol/server/stdio';
import * as fields from '../fields';
import { type AuditCapability, EXTENSION_ID } from '../models';
import {
  AFFINITY_HEADER,
  FORWARDED_HEADER,
  FORWARDED_VALUE,
  HEADER_MISMATCH,
  HEADER_MISMATCH_STATUS,
  instanceOfToken,
  isInstanceId,
  mintRoundToken,
  newInstanceId,
  ROUND_TOKEN_PREFIX,
} from './affinity';
import {
  CANCELLED_METHOD,
  DEFAULT_REQUEST_TIMEOUT_MS,
  type JsonRpcFrame,
  MAX_IDLE_SESSIONS,
  type McpAuditCall,
  McpAuditTransport,
  McpBindingError,
  type McpTransport,
  NO_OPEN_ROUND_MESSAGE,
  TOOLS_CALL_METHOD,
} from './seam';

export { NO_OPEN_ROUND_MESSAGE };

/**
 * How long a held call may go without a request in flight before its connection is closed. A round's
 * retry normally follows at once; one that asks the client for input waits on a person. The value matches
 * the lifetime the official `requestState` codec gives a round.
 */
export const DEFAULT_IDLE_TIMEOUT_MS = 600_000;

/** A request without `requestState` that carries the `session_id` of a call already held (§6.3). */
export const SESSION_OPEN_MESSAGE = 'this session is already open (§6.3)';
/** A forward whose request reached the owner, or may have, and whose answer did not come back (§6.4). */
export const FORWARD_UNKNOWN_MESSAGE = 'forwarding failed after the retry was sent; its outcome is unknown (§6.4)';
const PRINCIPAL_MISMATCH_MESSAGE = 'this round was opened by another principal (§6.4)';
const REGISTRY_FULL_MESSAGE = 'this instance holds as many audited calls as it may';
const CONNECTION_CLOSED_MESSAGE = 'the audited call ended before it answered this request';
const UNEXPECTED_RESULT_MESSAGE =
  'the tool answered tools/call with neither a CallToolResult nor an InputRequiredResult';

/** The most notifications of one request queued for delivery; beyond it they are dropped, and logged. */
export const MAX_QUEUED_NOTIFICATIONS = 256;

const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;
const METHOD_NOT_FOUND = -32601;
const PARSE_ERROR = -32700;
const SERVER_ERROR = -32000;
const MISSING_CLIENT_CAPABILITY = -32021;
/** JSON-RPC errors that are HTTP 400 wherever they arise, as the official handler's validation answers them. */
const BAD_REQUEST_CODES: ReadonlySet<number> = new Set([HEADER_MISMATCH, MISSING_CLIENT_CAPABILITY]);
const PAYLOAD_TOO_LARGE_STATUS = 413;
const BAD_REQUEST_STATUS = 400;
const INTERNAL_ERROR_STATUS = 500;
const OK_STATUS = 200;
const REDIRECT_STATUSES = { min: 300, max: 399 } as const;
const REQUEST_STATE = 'requestState';
const RESULT_TYPE = 'resultType';
const INPUT_REQUIRED = 'input_required';
const META = '_meta';
const JSON_MEDIA_TYPE = 'application/json';
const SSE_MEDIA_TYPE = 'text/event-stream';
const SESSION_BODY_PATH = `params._meta["${EXTENSION_ID}"].${fields.SESSION_ID}`;
const UNAVAILABLE_SERVER_INFO = { name: 'auditable-mcp-unavailable', version: '0.0.0' } as const;

/**
 * Connection-phase failures: the forwarded request never reached the owner, so nothing was performed there
 * and the retry can be refused as a replay is.
 */
const NOT_CONNECTED_CODES: ReadonlySet<string> = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
]);

/**
 * Hop-by-hop and framing headers a forwarder does not copy: they describe one connection, not the request.
 * `host` is set by the forwarder's own client from the target URL.
 */
const NOT_FORWARDED_REQUEST_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/** Response headers that describe the forwarder's own hop; the body is relayed already decoded. */
const NOT_RELAYED_RESPONSE_HEADERS = new Set([
  'connection',
  'content-encoding',
  'content-length',
  'keep-alive',
  'transfer-encoding',
]);

/**
 * Builds the tool's server for one serving unit. `audit` is the seam the server is served behind: a
 * `tools/call` handler obtains its call's audit transport with `audit.call(ctx.mcpReq.id)`, exactly as
 * over stdio, and reads the HTTP request it is being served under now from that call's `request` and
 * `authInfo` ({@link authInfoOf}). The factory is called once per held call, with the context of the
 * request that opened it, and once per request the official handler serves.
 */
export type AuditedServerFactory = (
  audit: McpAuditTransport,
  ctx: McpRequestContext,
) => McpServer | Server | Promise<McpServer | Server>;

/**
 * Thrown by a {@link RoundForwarder} when the forwarded request provably never reached the owner - it
 * could not connect, or was redirected - so the retry is refused as a replay is.
 */
export class ForwardNotDeliveredError extends McpBindingError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'ForwardNotDeliveredError';
    if (options?.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}

/**
 * Forwards a retry to the instance that holds its round, and resolves with that instance's response, which
 * is relayed verbatim. It resolves undefined when `instance` is not one this deployment knows, and throws
 * {@link ForwardNotDeliveredError} when the request never reached it; the retry is then refused. Any other
 * failure means the owner may have performed the retry, and is answered as an unknown outcome
 * ({@link FORWARD_UNKNOWN_MESSAGE}). It must never reach an instance the deployment did not register (§6.4).
 */
export type RoundForwarder = (instance: string, request: Request) => Promise<Response | undefined>;

/** The authenticated principal of a request, or undefined when the deployment knows none (§6.4). */
export type PrincipalOf = (
  request: Request,
  authInfo: AuthInfo | undefined,
) => string | undefined | Promise<string | undefined>;

export interface AuditableMcpHandlerOptions {
  /** The capability the tool declares (§6.1); every seam this entry builds declares it. */
  readonly declares: AuditCapability;
  /**
   * This instance's name, which every round token it issues carries: `[A-Za-z0-9_-]{1,64}`. Defaults to
   * one drawn at random when the entry is built, so a restarted process never claims an older token.
   */
  readonly instance?: string;
  /** Forwards a retry whose round another instance holds; see {@link fetchForwarder}. */
  readonly forward?: RoundForwarder;
  /**
   * The authenticated principal of a request. When given, each held call is bound to the principal of the
   * request that opened it, and a retry of the call that presents another one is refused, performing
   * nothing (§6.4). It is read where the round is held, so a forwarded retry is checked by its owner.
   */
  readonly principalOf?: PrincipalOf;
  /** The seam's bound on waiting for an attempt's answer (§6). */
  readonly requestTimeoutMs?: number;
  /** How long a held call may be idle before it is closed; see {@link DEFAULT_IDLE_TIMEOUT_MS}. */
  readonly idleTimeoutMs?: number;
  /**
   * The most calls this instance holds. Beyond it the least recently used call that has nothing under way
   * is closed; when every held call has work under way, a new audited call is refused.
   */
  readonly maxHeldCalls?: number;
  /** Hostnames an `Origin` header may name; when given, any other is refused with `403` (DNS rebinding). */
  readonly allowedOrigins?: string[];
  /**
   * Hostnames the `Host` header may name; when given, any other is refused with `403` (DNS rebinding). It
   * must include the hosts other instances forward to this one under.
   */
  readonly allowedHosts?: string[];
  /** Passed to the official handler: how 2025-era traffic is served. */
  readonly legacy?: 'stateless' | 'reject';
  /** Passed to the official handler, which answers every request, held calls' included. */
  readonly responseMode?: PerRequestResponseMode;
  readonly keepAliveMs?: number;
  /** The bound on a POST body, applied before anything is parsed. */
  readonly maxRequestBodySize?: number;
  /** Out-of-band errors, as the official handler reports them. */
  readonly onerror?: (error: Error) => void;
}

/** The web-standard face of the entry: serve one HTTP request and resolve with its response. */
export interface AuditableMcpHandler {
  /** The instance name this entry's round tokens carry. */
  readonly instance: string;
  readonly fetch: (request: Request, options?: McpHandlerRequestOptions) => Promise<Response>;
  /** Close every held call and the official handler. */
  readonly close: () => Promise<void>;
}

/** A JSON-RPC request as it was posted, before anything typed it. */
type RequestFrame = JsonRpcFrame & { id: string | number; method: string };

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * The authentication information a call is being served under now, as the MCP server package types it;
 * undefined where the request carried none.
 */
export function authInfoOf(call: McpAuditCall): AuthInfo | undefined {
  const info = call.authInfo;
  if (
    !isObject(info) ||
    typeof info.token !== 'string' ||
    typeof info.clientId !== 'string' ||
    !Array.isArray(info.scopes) ||
    !info.scopes.every((scope) => typeof scope === 'string')
  ) {
    return undefined;
  }
  return {
    token: info.token,
    clientId: info.clientId,
    scopes: info.scopes,
    ...(typeof info.expiresAt === 'number' ? { expiresAt: info.expiresAt } : {}),
    ...(info.resource instanceof URL ? { resource: info.resource } : {}),
    ...(isObject(info.extra) ? { extra: info.extra } : {}),
  };
}

function asRequestFrame(value: unknown): RequestFrame | undefined {
  if (!isObject(value) || value.jsonrpc !== '2.0' || typeof value.method !== 'string') {
    return undefined;
  }
  const { id, params } = value;
  if ((typeof id !== 'string' && typeof id !== 'number') || (params !== undefined && !isObject(params))) {
    return undefined;
  }
  return { jsonrpc: '2.0', id, method: value.method, ...(params === undefined ? {} : { params }) };
}

function metaOf(frame: JsonRpcFrame): Record<string, unknown> {
  const meta = frame.params?.[META];
  return isObject(meta) ? meta : {};
}

/** The `session_id` the body carries (§6.3), which is what the affinity header must mirror. */
function sessionInBody(frame: JsonRpcFrame): string | undefined {
  const carried = metaOf(frame)[EXTENSION_ID];
  const sessionId = isObject(carried) ? carried[fields.SESSION_ID] : undefined;
  return typeof sessionId === 'string' ? sessionId : undefined;
}

function requestStateOf(frame: JsonRpcFrame): string | undefined {
  const state = frame.params?.[REQUEST_STATE];
  return typeof state === 'string' ? state : undefined;
}

function withRequestState(frame: RequestFrame, state: string): RequestFrame {
  return { ...frame, params: { ...frame.params, [REQUEST_STATE]: state } };
}

function jsonRpcErrorResponse(
  status: number,
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): Response {
  return Response.json(
    { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } },
    { status, headers: { 'Content-Type': JSON_MEDIA_TYPE } },
  );
}

function echoableId(value: unknown): string | number | null {
  const id = isObject(value) ? value.id : undefined;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

function isJsonResponse(response: Response): boolean {
  return response.headers.get('content-type')?.toLowerCase().includes(JSON_MEDIA_TYPE) === true;
}

/**
 * Compare the affinity header with the body (§6.4). The header is never trusted over the body: absent
 * while the body carries a `session_id`, present while it carries none, or different, it is refused.
 */
function affinityMismatch(request: Request, frame: RequestFrame): Response | undefined {
  const header = request.headers.get(AFFINITY_HEADER);
  const body = sessionInBody(frame);
  if ((header ?? undefined) === body) {
    return undefined;
  }
  const detail =
    header === null
      ? `the body carries ${SESSION_BODY_PATH} but the ${AFFINITY_HEADER} header is absent`
      : body === undefined
        ? `the ${AFFINITY_HEADER} header is present but the body carries no ${SESSION_BODY_PATH}`
        : `the ${AFFINITY_HEADER} header does not match ${SESSION_BODY_PATH}`;
  return jsonRpcErrorResponse(
    HEADER_MISMATCH_STATUS,
    frame.id,
    HEADER_MISMATCH,
    `Bad Request: the request headers and body disagree: ${detail}`,
    { mismatch: { header: AFFINITY_HEADER, body: SESSION_BODY_PATH } },
  );
}

/**
 * A JSON answer of the audited path, with `-32020` and `-32021` given HTTP 400 wherever they arose: a
 * handler's error is otherwise in-band (200), and these two are request faults the official validation
 * answers with 400 (§6.4). A streamed answer is returned as it is.
 */
async function withBadRequestStatus(response: Response): Promise<Response> {
  if (response.status !== OK_STATUS || !isJsonResponse(response)) {
    return response;
  }
  const text = await response.text();
  let code: unknown;
  try {
    const parsed: unknown = JSON.parse(text);
    code = isObject(parsed) && isObject(parsed.error) ? parsed.error.code : undefined;
  } catch {
    code = undefined;
  }
  const status = typeof code === 'number' && BAD_REQUEST_CODES.has(code) ? BAD_REQUEST_STATUS : response.status;
  return new Response(text, {
    status,
    statusText: status === response.status ? response.statusText : '',
    headers: response.headers,
  });
}

/**
 * A transport that a seam can wrap before the transport it stands for exists. The official handler
 * constructs its per-request transport internally and connects the server to it, so the seam the factory
 * needs is built over this, and bound when the server is connected.
 */
class DeferredTransport implements McpTransport {
  #target: McpTransport | undefined;
  onmessage: McpTransport['onmessage'];
  onclose: (() => void) | undefined;
  onerror: ((error: Error) => void) | undefined;

  bind(target: McpTransport): void {
    this.#target = target;
    target.onmessage = (message, extra) => this.onmessage?.(message, extra);
    target.onclose = () => this.onclose?.();
    target.onerror = (error) => this.onerror?.(error);
  }

  #bound(): McpTransport {
    if (this.#target === undefined) {
      throw new McpBindingError('the seam was used before its server was connected');
    }
    return this.#target;
  }

  start(): Promise<void> {
    return this.#bound().start();
  }

  send(message: JsonRpcFrame | JsonRpcFrame[], options?: unknown): Promise<void> {
    return this.#bound().send(message, options);
  }

  close(): Promise<void> {
    return this.#target?.close() ?? Promise.resolve();
  }

  get hasPerRequestStream(): boolean {
    return this.#target?.hasPerRequestStream === true;
  }

  get sessionId(): string | undefined {
    return this.#target?.sessionId;
  }

  setProtocolVersion(version: string): void {
    this.#target?.setProtocolVersion?.(version);
  }

  setSupportedProtocolVersions(versions: string[]): void {
    this.#target?.setSupportedProtocolVersions?.(versions);
  }
}

/**
 * One end of an in-memory stream pair. Each message carries the context its sender gave (`context` in the
 * send options), which the other end hands its reader as the message's extra: the seam reads the HTTP
 * request and authentication information of each request of a held call from it.
 */
class LinkedWire implements McpTransport {
  #peer: LinkedWire | undefined;
  #closed = false;
  onmessage: McpTransport['onmessage'];
  onclose: (() => void) | undefined;
  onerror: ((error: Error) => void) | undefined;

  static pair(): [LinkedWire, LinkedWire] {
    const a = new LinkedWire();
    const b = new LinkedWire();
    a.#peer = b;
    b.#peer = a;
    return [a, b];
  }

  async start(): Promise<void> {}

  async send(message: JsonRpcFrame | JsonRpcFrame[], options?: unknown): Promise<void> {
    const peer = this.#peer;
    if (peer === undefined || this.#closed) {
      throw new McpBindingError('the held connection is closed');
    }
    if (Array.isArray(message)) {
      throw new McpBindingError('a JSON-RPC batch cannot be sent on a held connection (§6.5)');
    }
    peer.onmessage?.(message, isObject(options) ? options.context : undefined);
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    const peer = this.#peer;
    this.#peer = undefined;
    try {
      await peer?.close();
    } finally {
      this.onclose?.();
    }
  }
}

/** Why a retry this instance does not hold was forwarded, and what came of it. */
type ForwardResult =
  | { readonly kind: 'relayed'; readonly response: Response }
  | { readonly kind: 'not-delivered' }
  | { readonly kind: 'unknown' };

/** A request taken over from the official handler, found again by the request object it dispatches. */
type Takeover = {
  readonly request: Request;
  /** The body as it was posted, `requestState` included, which is what the held connection is given. */
  readonly frame: RequestFrame;
  /** The body as it was posted, for a forward. */
  readonly body: string;
  readonly authInfo: AuthInfo | undefined;
  /** The owner's response, when the retry was forwarded; it is what the client is answered with. */
  relayed: Response | undefined;
} & (
  | { readonly kind: 'retry'; readonly state: string; readonly sessionId: string | undefined }
  | { readonly kind: 'open'; readonly sessionId: string }
);

/** What a held call is given with each request: what the tool's handler reads through its call. */
interface RequestContextOf {
  readonly request: Request;
  readonly authInfo: AuthInfo | undefined;
}

/** A POST of a held call awaiting the connection's answer on its id. */
interface Exchange {
  readonly settle: (frame: JsonRpcFrame) => void;
  readonly notify: (frame: JsonRpcFrame) => void;
}

interface HeldCallSettings {
  readonly factory: AuditedServerFactory;
  readonly declares: AuditCapability;
  readonly instance: string;
  readonly requestTimeoutMs: number;
  readonly idleTimeoutMs: number;
  readonly onToken: (token: string, call: HeldCall) => void;
  readonly onClosed: (call: HeldCall) => void;
  readonly onerror: ((error: Error) => void) | undefined;
}

/**
 * One audited call's connection: the tool's server from the factory, served behind the seam over an
 * in-memory stream pair, as it would be over stdio.
 *
 * Every POST written into it is renumbered, because the ids of independent HTTP requests are chosen by
 * their clients and may repeat; the answer on the connection's id is the answer to that POST.
 */
class HeldCall {
  readonly sessionId: string;
  readonly principal: string | undefined;
  /** The round tokens the connection has issued and no retry has yet consumed. */
  readonly tokens = new Set<string>();
  readonly #settings: HeldCallSettings;
  readonly #wire: LinkedWire;
  readonly #seam: McpAuditTransport;
  readonly #served: StdioServerHandle;
  readonly #pending = new Map<number, Exchange>();
  /** The tool's own `requestState` of each of its input rounds, by the token that stands for it. */
  readonly #ownStates = new Map<string, string>();
  #nextId = 0;
  #idle: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  #factoryFailed = false;

  constructor(settings: HeldCallSettings, sessionId: string, principal: string | undefined, ctx: McpRequestContext) {
    this.#settings = settings;
    this.sessionId = sessionId;
    this.principal = principal;
    const [client, server] = LinkedWire.pair();
    const seam = new McpAuditTransport(server, settings.declares, {
      instance: settings.instance,
      requestTimeoutMs: settings.requestTimeoutMs,
    });
    this.#seam = seam;
    this.#served = serveStdio(
      async () => {
        try {
          return await settings.factory(seam, ctx);
        } catch (error) {
          this.#factoryFailed = true;
          throw error;
        }
      },
      {
        transport: seam,
        legacy: 'reject',
        ...(settings.onerror === undefined ? {} : { onerror: settings.onerror }),
      },
    );
    this.#wire = client;
    this.#wire.onmessage = (message) => this.#receive(message);
    this.#wire.onclose = () => void this.close();
  }

  /**
   * True when the call may be closed to make room (the held-call lifetime rule): no request of it is in
   * flight, it is not running (its handler waits for a round's retry, and every operation the host accepted
   * has its outcome), and it holds nothing the host has not yet received.
   */
  get evictable(): boolean {
    return this.#pending.size === 0 && !this.#seam.busy && !this.#seam.undelivered;
  }

  /** Whether `token` stands for one of the tool's own input rounds. */
  isOwnRound(token: string): boolean {
    return this.#ownStates.has(token);
  }

  /** The retry of `token` as the tool expects it: with the tool's own `requestState` where it stood for one. */
  resume(token: string, frame: RequestFrame): RequestFrame {
    this.tokens.delete(token);
    const own = this.#ownStates.get(token);
    if (own === undefined) {
      return frame;
    }
    this.#ownStates.delete(token);
    return withRequestState(frame, own);
  }

  /**
   * Write one request of the call into the connection and resolve with the frame answering it. Aborting
   * `signal` - the HTTP request was cancelled or its client went away - cancels the request as
   * `notifications/cancelled` does, which ends the call (§6.3).
   */
  exchange(
    frame: RequestFrame,
    context: RequestContextOf,
    signal: AbortSignal,
    notify: (frame: JsonRpcFrame) => void,
  ): Promise<JsonRpcFrame> {
    if (this.#closed) {
      return Promise.resolve(errorFrame(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE));
    }
    this.#stopIdle();
    this.#nextId += 1;
    const id = this.#nextId;
    return new Promise<JsonRpcFrame>((resolve) => {
      const onAbort = (): void => {
        if (this.#pending.delete(id)) {
          resolve(errorFrame(frame.id, INTERNAL_ERROR, CONNECTION_CLOSED_MESSAGE));
          void this.#cancel(id);
        }
      };
      this.#pending.set(id, {
        settle: (answer) => {
          signal.removeEventListener('abort', onAbort);
          resolve(answer);
        },
        notify,
      });
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
      this.#wire.send({ ...frame, id }, { context }).catch((error: unknown) => {
        console.error(`auditable-mcp: a request of audited session ${this.sessionId} could not be written`, error);
        this.#settle(id, errorFrame(frame.id, INTERNAL_ERROR, CONNECTION_CLOSED_MESSAGE));
      });
    });
  }

  /** Close the connection; every request still waiting on it is answered with an error. */
  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#stopIdle();
    for (const [id] of [...this.#pending]) {
      this.#settle(id, errorFrame(null, INTERNAL_ERROR, CONNECTION_CLOSED_MESSAGE));
    }
    this.#settings.onClosed(this);
    try {
      await this.#served.close();
    } catch (error) {
      console.error(`auditable-mcp: the connection of audited session ${this.sessionId} did not close cleanly`, error);
    }
  }

  async #cancel(id: number): Promise<void> {
    try {
      await this.#wire.send({ jsonrpc: '2.0', method: CANCELLED_METHOD, params: { requestId: id } });
    } catch (error) {
      console.error(`auditable-mcp: the cancellation of audited session ${this.sessionId} could not be written`, error);
    }
    await this.close();
  }

  #settle(id: number, frame: JsonRpcFrame): void {
    const exchange = this.#pending.get(id);
    if (exchange === undefined) {
      return;
    }
    this.#pending.delete(id);
    exchange.settle(frame);
    if (this.#pending.size === 0 && !this.#closed) {
      this.#startIdle();
    }
  }

  #receive(message: JsonRpcFrame): void {
    if (message.method === undefined && message.id !== undefined) {
      this.#answer(message);
      return;
    }
    if (message.method !== undefined && message.id !== undefined) {
      // MCP 2026-07-28 has no server-to-client request; the only peer on this connection is this entry.
      void this.#wire
        .send({
          jsonrpc: '2.0',
          id: message.id,
          error: { code: METHOD_NOT_FOUND, message: `${message.method} is not served on this connection` },
        })
        .catch((error: unknown) => console.error('auditable-mcp: a refusal could not be written', error));
      return;
    }
    // A notification on a stream carries nothing that relates it to a request. A held call has at most one
    // request in flight between rounds, so it goes with the latest.
    const latest = [...this.#pending.values()].at(-1);
    if (latest === undefined) {
      console.debug(`auditable-mcp: ${message.method ?? 'a message'} with no request in flight is dropped`);
      return;
    }
    latest.notify(message);
  }

  #answer(message: JsonRpcFrame): void {
    const id = message.id;
    if (typeof id !== 'number' || !this.#pending.has(id)) {
      console.debug(`auditable-mcp: an answer to ${String(id)} that no request awaits is dropped`);
      return;
    }
    const result = message.result;
    const state = result?.[REQUEST_STATE];
    const continues = result?.[RESULT_TYPE] === INPUT_REQUIRED;
    let answer = message;
    if (continues && result !== undefined && typeof state === 'string') {
      let token = state;
      if (!state.startsWith(ROUND_TOKEN_PREFIX)) {
        // The tool's own input round: its retry has to route and forward like one of the seam's (§6.4).
        token = mintRoundToken(this.#settings.instance);
        this.#ownStates.set(token, state);
        answer = { ...message, result: { ...result, [REQUEST_STATE]: token } };
      }
      this.tokens.add(token);
      this.#settings.onToken(token, this);
    }
    if (answer.error !== undefined && this.#factoryFailed) {
      console.error(`auditable-mcp: the factory failed for audited session ${this.sessionId}`);
      answer = errorFrame(message.id ?? null, INTERNAL_ERROR, CONNECTION_CLOSED_MESSAGE);
    }
    this.#settle(id, answer);
    if (!continues) {
      // A final result or an error ends the call, and its session with it (§6.3).
      void this.close();
    }
  }

  #startIdle(): void {
    this.#stopIdle();
    this.#idle = setTimeout(() => {
      if (this.#seam.busy) {
        // A running call is never expired: the entry does not cancel an accepted operation mid-flight,
        // whose outcome could not be known. It becomes eligible once it stops running.
        this.#startIdle();
        return;
      }
      console.warn(
        `auditable-mcp: audited session ${this.sessionId} was idle for ${this.#settings.idleTimeoutMs}ms and is ` +
          'closed; a retry of it will be refused',
      );
      void this.close();
    }, this.#settings.idleTimeoutMs);
    (this.#idle as { unref?: () => void }).unref?.();
  }

  #stopIdle(): void {
    if (this.#idle !== undefined) {
      clearTimeout(this.#idle);
      this.#idle = undefined;
    }
  }
}

function errorFrame(id: string | number | null, code: number, message: string): JsonRpcFrame {
  return { jsonrpc: '2.0', ...(id === null ? {} : { id }), error: { code, message } };
}

/** The result of a held call's answer, typed as the official `tools/call` handler returns it. */
function toolsCallResult(frame: JsonRpcFrame): CallToolResult | InputRequiredResult {
  if (frame.error !== undefined) {
    throw new ProtocolError(frame.error.code, frame.error.message, frame.error.data);
  }
  const result = frame.result;
  if (isInputRequiredResult(result) || isCallToolResult(result)) {
    return result;
  }
  throw new ProtocolError(INTERNAL_ERROR, UNEXPECTED_RESULT_MESSAGE);
}

/** One SSE `message` event carrying a JSON-RPC message, as both SDKs write it. */
function sseEvent(frame: JsonRpcFrame): Uint8Array {
  return new TextEncoder().encode(`event: message\r\ndata: ${JSON.stringify(frame)}\r\n\r\n`);
}

/**
 * A relayed SSE answer that, when the owner's stream breaks, ends with an event carrying the unknown
 * outcome for the request instead of breaking the client's connection: the headers are already sent,
 * so the stream is the only place left to say it (§6.4).
 */
function endingInBand(response: Response, id: string | number): Response {
  const body = response.body;
  if (body === null || response.headers.get('content-type')?.toLowerCase().includes(SSE_MEDIA_TYPE) !== true) {
    return response;
  }
  const reader = body.getReader();
  const relayed = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
        } else {
          controller.enqueue(value);
        }
      } catch (error) {
        console.error('auditable-mcp: a forwarded answer broke mid-stream; its outcome is unknown', error);
        controller.enqueue(sseEvent(errorFrame(id, INTERNAL_ERROR, FORWARD_UNKNOWN_MESSAGE)));
        controller.close();
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  return new Response(relayed, { status: response.status, statusText: response.statusText, headers: response.headers });
}

/** A server that answers `tools/call` with an error, standing in for one the factory failed to build. */
function unavailableServer(): Server {
  const server = new Server(UNAVAILABLE_SERVER_INFO, { capabilities: { tools: {} } });
  server.setRequestHandler(TOOLS_CALL_METHOD, () => {
    throw new ProtocolError(INTERNAL_ERROR, CONNECTION_CLOSED_MESSAGE);
  });
  return server;
}

/** Whether a failure of `fetch` happened before the request left: nothing reached the target. */
function neverConnected(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 4 && isObject(current); depth += 1) {
    const code = current.code;
    if (typeof code === 'string' && NOT_CONNECTED_CODES.has(code)) {
      return true;
    }
    current = current.cause;
  }
  return false;
}

/**
 * The tool's HTTP entry under MCP 2026-07-28, with round affinity (§6.4). See the module documentation.
 *
 * @throws {McpBindingError} `options.instance` is not a valid instance name.
 */
export function createAuditableMcpHandler(
  factory: AuditedServerFactory,
  options: AuditableMcpHandlerOptions,
): AuditableMcpHandler {
  const instance = options.instance ?? newInstanceId();
  if (!isInstanceId(instance)) {
    throw new McpBindingError(`${JSON.stringify(instance)} is not an instance name ([A-Za-z0-9_-]{1,64})`);
  }
  const maxRequestBodySize = options.maxRequestBodySize ?? DEFAULT_MAX_REQUEST_BODY_SIZE;
  const maxHeldCalls = options.maxHeldCalls ?? MAX_IDLE_SESSIONS;
  const seamOptions = { instance, requestTimeoutMs: options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS };
  const takeovers = new WeakMap<Request, Takeover>();
  /** Held calls by session, least recently used first. */
  const bySession = new Map<string, HeldCall>();
  const byToken = new Map<string, HeldCall>();
  let closed = false;

  const settings: HeldCallSettings = {
    factory,
    declares: options.declares,
    ...seamOptions,
    idleTimeoutMs: options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
    onToken: (token, call) => byToken.set(token, call),
    onClosed: (call) => {
      if (bySession.get(call.sessionId) === call) {
        bySession.delete(call.sessionId);
      }
      for (const token of call.tokens) {
        if (byToken.get(token) === call) {
          byToken.delete(token);
        }
      }
    },
    onerror: options.onerror,
  };

  /** Open a held call, first closing the least recently used one with nothing under way if the registry is full. */
  function open(sessionId: string, principal: string | undefined, ctx: McpRequestContext): HeldCall {
    if (bySession.size >= maxHeldCalls) {
      const evicted = [...bySession.values()].find((call) => call.evictable);
      if (evicted === undefined) {
        throw new ProtocolError(INTERNAL_ERROR, REGISTRY_FULL_MESSAGE);
      }
      console.warn(
        `auditable-mcp: more than ${maxHeldCalls} audited calls are held; session ${evicted.sessionId} is closed, ` +
          'and a retry of it will be refused',
      );
      void evicted.close();
    }
    const call = new HeldCall(settings, sessionId, principal, ctx);
    bySession.set(sessionId, call);
    return call;
  }

  function touch(call: HeldCall): void {
    if (bySession.get(call.sessionId) === call) {
      bySession.delete(call.sessionId);
      bySession.set(call.sessionId, call);
    }
  }

  async function forwardRetry(owner: string, takeover: Takeover): Promise<ForwardResult> {
    const forward = options.forward;
    if (forward === undefined) {
      return { kind: 'not-delivered' };
    }
    const { request } = takeover;
    try {
      const response = await forward(
        owner,
        new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: takeover.body,
          signal: request.signal,
        }),
      );
      return response === undefined ? { kind: 'not-delivered' } : { kind: 'relayed', response };
    } catch (error) {
      if (error instanceof ForwardNotDeliveredError) {
        console.error(`auditable-mcp: a retry did not reach instance ${owner}; it is refused`, error);
        return { kind: 'not-delivered' };
      }
      console.error(`auditable-mcp: forwarding a retry to instance ${owner} failed; its outcome is unknown`, error);
      return { kind: 'unknown' };
    }
  }

  /** The held call a retry resumes, forwarding it instead when another instance holds its round. */
  async function retryTarget(
    takeover: Takeover & { kind: 'retry' },
    principal: string | undefined,
  ): Promise<HeldCall | undefined> {
    const call = byToken.get(takeover.state);
    if (call === undefined) {
      const owner = instanceOfToken(takeover.state);
      if (owner !== undefined && owner !== instance && takeover.request.headers.get(FORWARDED_HEADER) === null) {
        const result = await forwardRetry(owner, takeover);
        if (result.kind === 'relayed') {
          takeover.relayed = endingInBand(result.response, takeover.frame.id);
          return undefined;
        }
        if (result.kind === 'unknown') {
          throw new ProtocolError(INTERNAL_ERROR, FORWARD_UNKNOWN_MESSAGE);
        }
      }
      // Consumed, concluded, expired, never issued here, or not forwardable: a replay the tool must not act
      // on, and never a call's first request (§6.4).
      throw new ProtocolError(INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE);
    }
    if (call.principal !== principal) {
      throw new ProtocolError(INVALID_PARAMS, PRINCIPAL_MISMATCH_MESSAGE);
    }
    if (call.isOwnRound(takeover.state) && takeover.sessionId !== call.sessionId) {
      // The tool's own round resumes only under the session that opened it; the seam's rounds check
      // this themselves (§6.4).
      throw new ProtocolError(INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE);
    }
    byToken.delete(takeover.state);
    return call;
  }

  /** Serve a taken-over `tools/call` from its held call, after the official handler validated it. */
  async function serveTakeover(takeover: Takeover, ctx: ServerContext): Promise<CallToolResult | InputRequiredResult> {
    const principal = await options.principalOf?.(takeover.request, takeover.authInfo);
    let call: HeldCall;
    let frame = takeover.frame;
    if (takeover.kind === 'retry') {
      const target = await retryTarget(takeover, principal);
      if (target === undefined) {
        // Answered with the owner's response; this result is discarded.
        return { content: [] };
      }
      call = target;
      frame = call.resume(takeover.state, frame);
    } else {
      if (bySession.has(takeover.sessionId)) {
        // The host issues a fresh session for every call, so this is no call's first request (§6.3).
        throw new ProtocolError(INVALID_PARAMS, SESSION_OPEN_MESSAGE);
      }
      call = open(takeover.sessionId, principal, {
        era: 'modern',
        requestInfo: takeover.request,
        ...(takeover.authInfo === undefined ? {} : { authInfo: takeover.authInfo }),
      });
    }
    touch(call);
    // Notifications go out in order and ahead of the answer, as they would on the call's own stream.
    let delivered = Promise.resolve();
    let queued = 0;
    const answer = await call.exchange(
      frame,
      { request: takeover.request, authInfo: takeover.authInfo },
      ctx.mcpReq.signal,
      (notification) => {
        const method = notification.method;
        if (method === undefined) {
          return;
        }
        if (queued >= MAX_QUEUED_NOTIFICATIONS) {
          console.debug(`auditable-mcp: ${method} of a held call is dropped: ${queued} are already queued`);
          return;
        }
        queued += 1;
        delivered = delivered
          .then(() =>
            ctx.mcpReq.notify({
              method,
              ...(notification.params === undefined ? {} : { params: notification.params }),
            }),
          )
          .catch((error: unknown) => console.debug(`auditable-mcp: ${method} of a held call was not delivered`, error))
          .finally(() => {
            queued -= 1;
          });
      },
    );
    await delivered;
    return toolsCallResult(answer);
  }

  /**
   * The server the official handler dispatches a request into. For a taken-over request it is a server
   * from the factory whose `tools/call` handler serves the request from its held call; its own tool
   * handlers never run, and it exists so that the official handler validates the request against the
   * tool's own declarations. For any other request it is a server from the factory served behind a seam
   * of its own.
   */
  async function officialFactory(ctx: McpRequestContext): Promise<McpServer | Server> {
    const takeover = ctx.requestInfo === undefined ? undefined : takeovers.get(ctx.requestInfo);
    const deferred = new DeferredTransport();
    const seam = new McpAuditTransport(deferred, options.declares, seamOptions);
    if (takeover !== undefined) {
      let product: McpServer | Server;
      try {
        product = await factory(seam, ctx);
      } catch (error) {
        console.error('auditable-mcp: the factory failed for an audited request; it is answered with an error', error);
        return unavailableServer();
      }
      const server = product instanceof McpServer ? product.server : product;
      server.setRequestHandler(TOOLS_CALL_METHOD, (_request, handlerCtx) => serveTakeover(takeover, handlerCtx));
      return product;
    }
    const product = await factory(seam, ctx);
    // The official handler builds the per-request transport itself and connects the server to it; the seam
    // has to stand between the two, so the connection is made through it.
    const connect = product.connect.bind(product);
    product.connect = (transport: Transport): Promise<void> => {
      deferred.bind(transport);
      return connect(seam);
    };
    return product;
  }

  const official = createMcpHandler(officialFactory, {
    ...(options.legacy === undefined ? {} : { legacy: options.legacy }),
    ...(options.responseMode === undefined ? {} : { responseMode: options.responseMode }),
    ...(options.keepAliveMs === undefined ? {} : { keepAliveMs: options.keepAliveMs }),
    ...(options.onerror === undefined ? {} : { onerror: options.onerror }),
    maxRequestBodySize,
  });

  async function handle(request: Request, requestOptions: McpHandlerRequestOptions | undefined): Promise<Response> {
    const guarded =
      (options.allowedHosts === undefined ? undefined : hostHeaderValidationResponse(request, options.allowedHosts)) ??
      (options.allowedOrigins === undefined ? undefined : originValidationResponse(request, options.allowedOrigins));
    if (guarded !== undefined) {
      return guarded;
    }
    if (request.method.toUpperCase() !== 'POST' || !isJsonContentType(request.headers.get('content-type'))) {
      return official.fetch(request, requestOptions);
    }
    let body: unknown = requestOptions?.parsedBody;
    let text: string | undefined;
    let passOn = request;
    if (body === undefined) {
      passOn = request.clone();
      let read: Awaited<ReturnType<typeof readRequestBody>>;
      try {
        read = await readRequestBody(request, maxRequestBodySize);
      } catch {
        return jsonRpcErrorResponse(
          BAD_REQUEST_STATUS,
          null,
          PARSE_ERROR,
          'Parse error: the request body could not be read',
        );
      }
      if (read.tooLarge) {
        return jsonRpcErrorResponse(
          PAYLOAD_TOO_LARGE_STATUS,
          null,
          SERVER_ERROR,
          `Payload Too Large: Request body must not exceed ${maxRequestBodySize} bytes`,
        );
      }
      text = read.text;
      try {
        body = JSON.parse(text);
      } catch {
        // Not JSON: the official handler owns that answer.
        return official.fetch(passOn, requestOptions);
      }
    }
    const frame = asRequestFrame(body);
    if (frame === undefined || typeof metaOf(frame)[PROTOCOL_VERSION_META_KEY] !== 'string') {
      return official.fetch(passOn, requestOptions);
    }
    const mismatch = affinityMismatch(request, frame);
    if (mismatch !== undefined) {
      options.onerror?.(new Error(`Rejected inbound request (${AFFINITY_HEADER}): the header disagrees with the body`));
      return mismatch;
    }
    if (frame.method !== TOOLS_CALL_METHOD) {
      return official.fetch(passOn, requestOptions);
    }
    const sessionId = sessionInBody(frame);
    const state = requestStateOf(frame);
    const key =
      state !== undefined && (sessionId !== undefined || state.startsWith(ROUND_TOKEN_PREFIX))
        ? { kind: 'retry' as const, state, sessionId }
        : state === undefined && sessionId !== undefined
          ? { kind: 'open' as const, sessionId }
          : undefined;
    if (key === undefined) {
      return official.fetch(passOn, requestOptions);
    }
    // The official handler validates what it sees; `requestState` is left out of it, since the held
    // connection's own server is what verifies a tool's state, and a round token is this entry's.
    const { [REQUEST_STATE]: _state, ...params } = frame.params ?? {};
    const takeover: Takeover = {
      request,
      frame,
      body: text ?? JSON.stringify(body),
      authInfo: requestOptions?.authInfo,
      relayed: undefined,
      ...key,
    };
    takeovers.set(request, takeover);
    let response: Response;
    try {
      response = await official.fetch(request, { ...requestOptions, parsedBody: { ...frame, params } });
    } finally {
      takeovers.delete(request);
    }
    if (takeover.relayed !== undefined) {
      await response.body?.cancel();
      return takeover.relayed;
    }
    return withBadRequestStatus(response);
  }

  return {
    instance,
    fetch: async (request, requestOptions) => {
      if (closed) {
        throw new Error('This MCP handler has been closed');
      }
      try {
        return await handle(request, requestOptions);
      } catch (error) {
        options.onerror?.(error instanceof Error ? error : new Error(String(error)));
        return jsonRpcErrorResponse(
          INTERNAL_ERROR_STATUS,
          echoableId(requestOptions?.parsedBody),
          INTERNAL_ERROR,
          'Internal server error',
        );
      }
    },
    close: async () => {
      closed = true;
      await Promise.all([...bySession.values()].map((call) => call.close()));
      await official.close();
    },
  };
}

/** Options for {@link fetchForwarder}. */
export interface FetchForwarderOptions {
  /**
   * The base URL of the MCP endpoint of `instance`, or undefined when the deployment does not know it. It
   * is given only a well-formed instance name taken from a round token, and must answer from the
   * deployment's own registry: a URL built from the name would let a client choose where this instance
   * sends requests. One that throws is treated as not knowing the instance.
   */
  readonly resolve: (instance: string) => string | URL | undefined | Promise<string | URL | undefined>;
  /**
   * The fetch implementation; the global one by default. Its read timeout must be unbounded, or longer than
   * any operation the tool performs: a forward cut short after the owner received it is answered as an
   * unknown outcome, never as a refusal.
   */
  readonly fetch?: (input: string | URL, init: RequestInit) => Promise<Response>;
}

/**
 * A {@link RoundForwarder} over `fetch`: it resolves the instance through the deployment's registry, sends
 * the request there with its headers - authorization included - and `Auditable-Mcp-Forwarded: 1`, and
 * relays the response. An instance the registry does not know is not forwarded to; a request that could
 * not connect, or that was answered with a redirect, never reached the owner ({@link ForwardNotDeliveredError}).
 * A JSON answer is read whole before it is relayed, so a failure while reading it is an unknown outcome
 * rather than a truncated answer; a streamed answer is relayed as it arrives.
 */
export function fetchForwarder(options: FetchForwarderOptions): RoundForwarder {
  const send = options.fetch ?? ((input: string | URL, init: RequestInit) => fetch(input, init));
  return async (instance, request) => {
    if (!isInstanceId(instance)) {
      return undefined;
    }
    let target: string | URL | undefined;
    try {
      target = await options.resolve(instance);
    } catch (error) {
      console.error(`auditable-mcp: resolving instance ${instance} failed; it is not forwarded to`, error);
      return undefined;
    }
    if (target === undefined) {
      return undefined;
    }
    const headers = new Headers();
    request.headers.forEach((value, name) => {
      if (!NOT_FORWARDED_REQUEST_HEADERS.has(name.toLowerCase())) {
        headers.set(name, value);
      }
    });
    headers.set(FORWARDED_HEADER, FORWARDED_VALUE);
    let upstream: Response;
    try {
      upstream = await send(target, {
        method: request.method,
        headers,
        body: await request.text(),
        signal: request.signal,
        redirect: 'manual',
      });
    } catch (error) {
      if (neverConnected(error)) {
        throw new ForwardNotDeliveredError(`the forward to instance ${instance} could not connect`, { cause: error });
      }
      throw error;
    }
    if (upstream.status >= REDIRECT_STATUSES.min && upstream.status <= REDIRECT_STATUSES.max) {
      await upstream.body?.cancel();
      throw new ForwardNotDeliveredError(`the forward to instance ${instance} was redirected (${upstream.status})`);
    }
    const relayed = new Headers();
    upstream.headers.forEach((value, name) => {
      if (!NOT_RELAYED_RESPONSE_HEADERS.has(name.toLowerCase())) {
        relayed.set(name, value);
      }
    });
    const body = isJsonResponse(upstream) ? await upstream.text() : upstream.body;
    return new Response(body, { status: upstream.status, statusText: upstream.statusText, headers: relayed });
  };
}
