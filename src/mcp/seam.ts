/**
 * Carrying the §6 exchange on an MCP connection, in both bindings (§6.4, §6.5).
 *
 * Neither official MCP SDK can deliver this extension through its own dispatch, and neither needs to:
 * everything it adds is ordinary JSON-RPC on the connection MCP already holds. So this binding sits one
 * layer lower, between the session and the transport. A `Transport` is something the integrator hands to
 * the session, so each side wraps the real one and hands the session a seam instead; the audit traffic is
 * handled here, and every other message passes through untouched and in order, so the session sees
 * exactly the MCP it would have seen without this extension.
 *
 * Which binding a call uses is read from the call itself. A `tools/call` that carries the protocol
 * version in its `_meta` is made under MCP `2026-07-28`, and §6.4 applies: the host's declaration comes
 * with the request, and the exchange rides the call as Multi Round-Trip Requests. Any other call is made
 * under a version with an initialization handshake, and §6.5 applies: the declaration came with
 * `initialize`, and the exchange is `audit/attempt` and `audit/outcome`.
 *
 * Under §6.4 the tool's handler is not rewritten into rounds. It awaits its attempts as it would under
 * §6.5; this seam ends the round for it with an `InputRequiredResult`, keeps the handler suspended until
 * the host's retry arrives, hands it the answers, and puts the handler's final result on the retry's id.
 * The retry never reaches the tool's session. That works where the retry reaches the process that holds
 * the suspended handler, and this SDK does not serialize a handler into `requestState`; the specification
 * does not constrain the mechanism (§6.4, round affinity). Over stdio the retry comes back on the same
 * connection. Over Streamable HTTP, where each request is a POST of its own, the HTTP entry
 * (`auditable-mcp-sdk/mcp/http`) gives each audited call a connection of its own in memory and runs this
 * seam over it, and every round token names the instance that issued it: a retry reaches that instance by
 * a router that reads `Auditable-Mcp-Session`, or by being forwarded, and is otherwise refused as a replay
 * is, with nothing performed.
 *
 * The host's side is symmetric: it issues the audit session in each outgoing `tools/call`, seals what
 * comes back, answers a round that asks for nothing else by retrying on the spot, and closes the session
 * when the call ends (§6.3).
 */

import type { NegotiationResult } from '../capability';
import { NegotiationOutcome, negotiate } from '../capability';
import * as fields from '../fields';
import {
  type AttemptResponse,
  type AuditCapability,
  attemptResponseSchema,
  auditRequestMetaSchema,
  EXTENSION_ID,
  Outcome,
  Status,
} from '../models';
import { newSessionId, SessionNumbering } from '../session';
import { AmcpUsageError, type AuditEndpoint, type AuditTransport, unavailable } from '../transport';
import { isInstanceId, mintRoundToken, PROCESS_INSTANCE, ROUND_TOKEN_PREFIX, withAffinityHeader } from './affinity';
import { capabilityOf, declareInto, type WithExtensions } from './declaration';

/** §6.5's methods. `params` IS the audit event object, never a wrapper. */
export const ATTEMPT_METHOD = 'audit/attempt';
export const OUTCOME_METHOD = 'audit/outcome';
export const TOOLS_CALL_METHOD = 'tools/call';
export const CANCELLED_METHOD = 'notifications/cancelled';
export const INITIALIZE_METHOD = 'initialize';
export const DISCOVER_METHOD = 'server/discover';
/** Where MCP 2026-07-28 carries a request's protocol version and the client's capabilities. */
const PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion';
const CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities';
/** The protocol versions that carry their version per request, and so bind as §6.4. */
const MODERN_PROTOCOL_VERSIONS: readonly string[] = ['2026-07-28'];

/** The MRTR members of a result and of a retry (MCP 2026-07-28), as they appear on the wire. */
const RESULT_TYPE = 'resultType';
const INPUT_REQUIRED = 'input_required';
const INPUT_REQUESTS = 'inputRequests';
const REQUEST_STATE = 'requestState';
const META = '_meta';
const TASK = 'task';

/**
 * Request ids this seam mints are strings under this prefix. An MCP session numbers its own requests
 * with integers, so the two id spaces cannot collide however long either side runs.
 */
export const ID_PREFIX = 'amcp-';

export { ROUND_TOKEN_PREFIX };

/** §6 leaves the bound on the wait to the binding, requiring only that it fail closed. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/**
 * The most rounds a host follows in one call (§8.3 leaves the bound to the host). A call that asks for
 * more is ended: the host stops retrying, closes the session, and answers the client with an error.
 */
export const MAX_ROUNDS_PER_CALL = 256;

/**
 * The most idle audit sessions a tool keeps per connection. A session is idle when the handler answered
 * with its own `input_required` and no request of the call is in flight: the client's retry may come at
 * any time, or never. Beyond this bound the least recently used idle session is evicted; a retry of it
 * then starts its numbering again, which the host refuses, so the call fails closed.
 *
 * The same bound applies, each on its own, to the calls a tool keeps for a round's retry after their
 * handler concluded, and to the rounds a host holds for its client's retry.
 */
export const MAX_IDLE_SESSIONS = 1024;

/** The JSON-RPC error message a retry whose `requestState` names no open round is refused with (§6.4). */
export const NO_OPEN_ROUND_MESSAGE = 'this requestState names no open round (§6.4)';

/** JSON-RPC error codes this binding answers with. */
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;
const INVALID_REQUEST = -32600;

/**
 * A JSON-RPC message as it crosses the transport, before either side has typed it.
 *
 * Every member but `jsonrpc` admits `undefined`, so each member of the official `JSONRPCMessage` union is
 * assignable to it under `exactOptionalPropertyTypes`.
 */
export interface JsonRpcFrame {
  jsonrpc: '2.0';
  id?: string | number | undefined;
  method?: string | undefined;
  params?: Record<string, unknown> | undefined;
  result?: Record<string, unknown> | undefined;
  error?: { code: number; message: string; data?: unknown } | undefined;
}

/**
 * A message handler, declared with method syntax so that it is compared bivariantly: the official
 * transports type `onmessage` as generic over their own message union, which a structural frame type can
 * only meet in one direction.
 */
type FrameHandler = { bivarianceHack(message: JsonRpcFrame, extra?: unknown): void }['bivarianceHack'];

/**
 * The MCP transport surface this binding wraps and presents.
 *
 * Declared structurally rather than imported, so nothing here depends on the MCP package: an official
 * `Transport` satisfies it, and a seam satisfies an official `Transport`, with no cast in either direction.
 */
export interface McpTransport {
  start(): Promise<void>;
  /** A seam sends one message per frame (§6.5); the array form is admitted so a batching transport fits. */
  send(message: JsonRpcFrame | JsonRpcFrame[], options?: unknown): Promise<void>;
  close(): Promise<void>;
  /** Set by the Streamable HTTP transports; it decides how the session cancels a request. */
  readonly hasPerRequestStream?: boolean | undefined;
  onmessage?: FrameHandler | undefined;
  onclose?: (() => void) | undefined;
  onerror?: ((error: Error) => void) | undefined;
  sessionId?: string | undefined;
  setProtocolVersion?: ((version: string) => void) | undefined;
  /** Called during connect, for the header validation an HTTP transport performs. */
  setSupportedProtocolVersions?: ((versions: string[]) => void) | undefined;
}

/** The binding was driven into a state §6 does not define. */
export class McpBindingError extends AmcpUsageError {
  constructor(message: string) {
    super(message);
    this.name = 'McpBindingError';
  }
}

/** Negotiation was asked for, under §6.5, before the peer's `initialize` reached this seam (§6.1). */
export class HandshakeNotSeenError extends McpBindingError {
  constructor(message: string) {
    super(message);
    this.name = 'HandshakeNotSeenError';
  }
}

/** A send was attempted for a call that is not audit-negotiated (§6.2). */
export class UnnegotiatedSendError extends McpBindingError {
  constructor(message: string) {
    super(message);
    this.name = 'UnnegotiatedSendError';
  }
}

/** A call was asked for that is not a `tools/call` in flight on this connection. */
export class UnknownCallError extends McpBindingError {
  constructor(message: string) {
    super(message);
    this.name = 'UnknownCallError';
  }
}

/** A value that is settled once; later settlements are ignored. */
class Once<T> {
  readonly settled: Promise<T>;
  #resolve: (value: T) => void = () => {};
  #done = false;

  constructor() {
    this.settled = new Promise<T>((resolve) => {
      this.#resolve = resolve;
    });
  }

  /** Settle with `value`; false when an earlier settlement stands. */
  settle(value: T): boolean {
    if (this.#done) {
      return false;
    }
    this.#done = true;
    this.#resolve(value);
    return true;
  }
}

/** One attempt in flight, waiting for the host's answer. The first answer stands. */
type Pending = Once<AttemptResponse>;

/** Settle every attempt in `awaiting` as unanswered (§6), and empty it. */
function unanswered(awaiting: Map<string, Pending>): void {
  for (const pending of awaiting.values()) {
    pending.settle(unavailable());
  }
  awaiting.clear();
}

/** A frame that expects a response: it names a method and carries an id to answer under. */
type RequestFrame = JsonRpcFrame & { id: string | number; method: string };

function isRequest(frame: JsonRpcFrame): frame is RequestFrame {
  return frame.method !== undefined && frame.id !== undefined;
}

function isNotification(frame: JsonRpcFrame): boolean {
  return frame.method !== undefined && frame.id === undefined;
}

function isResponse(frame: JsonRpcFrame): frame is JsonRpcFrame & { id: string | number } {
  return frame.method === undefined && frame.id !== undefined;
}

/** A JSON-RPC id as a map key: `1` and `"1"` are different requests. */
function idKey(id: unknown): string {
  return `${typeof id}:${String(id)}`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * An item of a round's `events` that the retry's `responses` can answer: an attempt with a string `id`
 * (§6.4). Any other item - an outcome, or one that is no event at all - has no response and is recorded.
 */
function isAnswerableAttempt(item: unknown): item is Record<string, unknown> & { [fields.ID]: string } {
  return isObject(item) && item[fields.OUTCOME] === Outcome.ATTEMPTED && typeof item[fields.ID] === 'string';
}

function metaOf(params: Record<string, unknown> | undefined): Record<string, unknown> {
  const meta = params?.[META];
  return isObject(meta) ? meta : {};
}

/** Only an object-valued `task` asks for task augmentation; `null` or any other value does not (§6.4). */
function isTaskAugmented(params: Record<string, unknown>): boolean {
  return isObject(params[TASK]);
}

/** Run `fn` after `ms`, without the timer alone keeping the process alive where the runtime allows. */
function after(ms: number, fn: () => void): ReturnType<typeof setTimeout> {
  const timer = setTimeout(fn, ms);
  (timer as { unref?: () => void }).unref?.();
  return timer;
}

/** True when a request is made under MCP 2026-07-28, which puts its version in `_meta` (§6.4). */
function isModern(params: Record<string, unknown> | undefined): boolean {
  return MODERN_PROTOCOL_VERSIONS.includes(String(metaOf(params)[PROTOCOL_VERSION_META_KEY]));
}

/** Read an Attempt Response, treating anything unreadable as a failure to record (§6, §7.2). */
function readResponse(value: unknown, what: string): AttemptResponse {
  const parsed = attemptResponseSchema.safeParse(value);
  if (!parsed.success) {
    console.error(`auditable-mcp: ${what} answered with an unreadable Attempt Response`, parsed.error.message);
    return unavailable();
  }
  return parsed.data;
}

function sameCapability(a: AuditCapability, b: AuditCapability): boolean {
  return (
    a.spec_version === b.spec_version &&
    a.level === b.level &&
    a.attempt === b.attempt &&
    a.countersign === b.countersign
  );
}

/** Whether a tool's answer ends its call: an error, or a result that is not an input round (§6.4). */
function concludes(frame: JsonRpcFrame): boolean {
  return frame.error !== undefined || frame.result?.[RESULT_TYPE] !== INPUT_REQUIRED;
}

/** Race `settled` against `timeoutMs`; undefined when the timeout came first. */
async function bounded<T>(settled: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), timeoutMs);
  });
  try {
    return await Promise.race([settled, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Stream plumbing shared by both roles: pass MCP through, handle the audit traffic here.
 *
 * The seam is what the session is given, so the session's own `onmessage` is held here and called for
 * everything this side does not keep. By default inbound frames are handled one at a time, in arrival
 * order: §6 requires the events of a call to be processed in the order the tool emitted them, and a
 * handler that awaits the endpoint would otherwise let a later frame overtake it. A role may order them
 * more finely (`enqueue`).
 */
abstract class FrameSeam implements McpTransport {
  protected readonly inner: McpTransport;
  #inbound: Promise<void> = Promise.resolve();
  #nextId = 0;
  #sessionMessage: FrameHandler | undefined;
  #sessionClose: (() => void) | undefined;

  protected constructor(inner: McpTransport) {
    this.inner = inner;
    inner.onmessage = (message, extra) => {
      this.enqueue(message, extra);
    };
    inner.onclose = () => {
      void this.onConnectionLost().finally(() => this.#sessionClose?.());
    };
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  async close(): Promise<void> {
    await this.onConnectionLost();
    await this.inner.close();
  }

  /**
   * Everything the session writes passes through, after this side's own additions. A JSON-RPC batch is
   * refused rather than passed on: this seam reads one message per frame, and a batch would carry its
   * members past it unaudited (§6.5).
   *
   * @throws {McpBindingError} `message` is a batch.
   */
  async send(message: JsonRpcFrame, options?: unknown): Promise<void> {
    const sent: unknown = message;
    if (Array.isArray(sent)) {
      throw new McpBindingError('a JSON-RPC batch cannot be sent through the audit binding (§6.5)');
    }
    const forward = await this.outbound(message);
    if (forward !== undefined) {
      await this.inner.send(forward, this.outboundOptions(forward, options));
    }
  }

  set onmessage(handler: FrameHandler | undefined) {
    this.#sessionMessage = handler;
  }

  get onmessage(): FrameHandler | undefined {
    return this.#sessionMessage;
  }

  set onclose(handler: (() => void) | undefined) {
    this.#sessionClose = handler;
  }

  get onclose(): (() => void) | undefined {
    return this.#sessionClose;
  }

  set onerror(handler: ((error: Error) => void) | undefined) {
    this.inner.onerror = handler;
  }

  get onerror(): ((error: Error) => void) | undefined {
    return this.inner.onerror;
  }

  get sessionId(): string | undefined {
    return this.inner.sessionId;
  }

  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }

  setSupportedProtocolVersions(versions: string[]): void {
    this.inner.setSupportedProtocolVersions?.(versions);
  }

  /**
   * Every member of the wrapped transport reaches the session, this one included.
   *
   * The session reads it to choose how it cancels a request: on a per-request-stream transport it aborts
   * that stream, and otherwise it sends `notifications/cancelled`. A seam that reported `false` for a
   * transport that sets it would change how ordinary MCP behaves on this connection, which §6.2 does not
   * permit this extension to do. The session tests it with `=== true`, so an unset member reads as `false`.
   */
  get hasPerRequestStream(): boolean {
    return this.inner.hasPerRequestStream === true;
  }

  /** Send one JSON-RPC message of this seam's own. One message per frame, never an array (§6.5). */
  protected async sendFrame(frame: JsonRpcFrame, relatedRequestId?: string | number): Promise<void> {
    await this.inner.send(frame, relatedRequestId === undefined ? undefined : { relatedRequestId });
  }

  /** Deliver a frame to the session as if it had arrived from the transport. */
  protected deliver(frame: JsonRpcFrame, extra?: unknown): void {
    this.#sessionMessage?.(frame, extra);
  }

  /** Return the next request id in the string space the session never uses. */
  protected newId(): string {
    this.#nextId += 1;
    return `${ID_PREFIX}${this.#nextId}`;
  }

  /** Schedule an inbound frame. By default every frame waits for the one before it. */
  protected enqueue(message: JsonRpcFrame, extra?: unknown): void {
    this.#inbound = this.#inbound.then(() => this.receive(message, extra));
  }

  /** Handle one inbound frame and deliver what the session should see. Never rejects. */
  protected async receive(message: JsonRpcFrame, extra?: unknown): Promise<void> {
    try {
      const forward = await this.inbound(message, extra);
      if (forward !== undefined) {
        this.deliver(forward, extra);
      }
    } catch (error) {
      console.error('auditable-mcp: the audit binding could not handle an inbound frame', error);
    }
  }

  /** Handle an inbound frame; return what the session should see, or undefined. */
  protected abstract inbound(frame: JsonRpcFrame, extra?: unknown): Promise<JsonRpcFrame | undefined>;

  /** Handle an outbound frame; return what the peer should see, or undefined. */
  protected async outbound(frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    return frame;
  }

  /** The send options an outbound frame goes with; the session's own, unchanged, by default. */
  protected outboundOptions(_frame: JsonRpcFrame, options: unknown): unknown {
    return options;
  }

  /** Release anything the role is holding. Nothing by default. */
  protected async onConnectionLost(): Promise<void> {}
}

/**
 * What the session gave a request to carry besides its body, on a transport that sends one request per
 * HTTP request: its request metadata headers (the `Mcp-Param-*` a `tools/call` mirrors from its
 * arguments) and the signal that cancels it. Transports that share one channel ignore both.
 */
interface PerRequest {
  readonly headers: Readonly<Record<string, string>> | undefined;
  readonly requestSignal: AbortSignal | undefined;
}

function perRequestOf(options: unknown): PerRequest {
  if (!isObject(options)) {
    return { headers: undefined, requestSignal: undefined };
  }
  const carried = options.headers;
  const headers = isObject(carried)
    ? Object.fromEntries(
        Object.entries(carried).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
      )
    : undefined;
  const signal = options.requestSignal;
  return { headers, requestSignal: signal instanceof AbortSignal ? signal : undefined };
}

/** One round of a §6.4 call that is out: the token it was issued under, and the attempts it carried. */
interface Round {
  readonly token: string;
  readonly awaiting: Map<string, Pending>;
}

/**
 * An audit session the host issued, as the tool sees it across the requests of one call (§6.3, §6.4).
 *
 * Under §6.4 one call can reach the tool as several requests - the tool's own `inputRequests` rounds are
 * retried as new requests that the tool's session serves - and every one carries the same `session_id`.
 * What holds for the whole call is kept here: the host's declaration and the §6.1 result from the call's
 * first request, and the `signer_seq` numbering, which continues rather than restarting with each request.
 */
interface ToolSession {
  readonly sessionId: string;
  readonly hostCapability: AuditCapability | undefined;
  readonly numbering: SessionNumbering;
  negotiation: NegotiationResult | undefined;
  /** Requests carrying the session that are in flight on this connection. */
  live: number;
}

/** A `tools/call` request this tool is serving, and the state of its audit exchange. */
interface ToolCall {
  readonly originalId: string | number;
  readonly modern: boolean;
  /** The host's declaration, as the call's first request carried it (§6.1, §6.4). */
  readonly hostCapability: AuditCapability | undefined;
  /** The session the host issued with the call, if it issued one (§6.3). */
  readonly session: ToolSession | undefined;
  /** The session this tool issues for itself when the call is not negotiated (§6.2, §6.3). */
  readonly ownSessionId: string;
  readonly taskAugmented: boolean;
  readonly numbering: SessionNumbering;
  /** Every id the request has been served under - the original and each retry - by `idKey`. */
  readonly ids: Set<string>;
  /** The id the next frame goes out on; undefined while a round is out and its retry has not come. */
  currentId: string | number | undefined;
  negotiated: boolean;
  /** §6.4: the events emitted since the last round, and the attempts among them. */
  buffered: Record<string, unknown>[];
  nextAwaiting: Map<string, Pending>;
  round: Round | undefined;
  roundScheduled: boolean;
  finished: boolean;
  cancelled: boolean;
  /**
   * The handler's final frame, when it concluded while a round was out: it goes on that round's retry,
   * however late (§6.4).
   */
  held: JsonRpcFrame | undefined;
  /** Attempts the host accepted whose outcome the handler has not yet emitted: operations under way. */
  readonly accepted: Set<string>;
  /** What the transport gave with the request of the call being served now: the original, or a retry. */
  extra: unknown;
}

function extraMember(extra: unknown, name: string): unknown {
  return isObject(extra) ? extra[name] : undefined;
}

/**
 * The tool's audit transport for one `tools/call` (§6.3): an `AuditTransport` for that call alone.
 *
 * Obtain it from `McpAuditTransport.call` with the request id the MCP handler is serving. Its `sessionId`
 * is the audit session the host issued for the call when the call is audit-negotiated, and otherwise one
 * minted here for a tool that takes the degraded posture - never the peer's (§6.2, §6.3).
 */
export class McpAuditCall implements AuditTransport {
  readonly #seam: McpAuditTransport;
  readonly #call: ToolCall;

  /** @internal Constructed by {@link McpAuditTransport.call}. */
  constructor(seam: McpAuditTransport, call: ToolCall) {
    this.#seam = seam;
    this.#call = call;
  }

  /** The audit session every event of this call carries (§6.3). */
  get sessionId(): string {
    return this.#call.negotiated && this.#call.session !== undefined
      ? this.#call.session.sessionId
      : this.#call.ownSessionId;
  }

  /**
   * The call's `signer_seq` numbering (§7.4): one object for every request carrying the call's session,
   * so every `AmcpSession` over this call numbers one sequence.
   */
  get numbering(): SessionNumbering {
    return this.#call.numbering;
  }

  /** What the host declared for this call, or undefined if it declared nothing readable (§6.1). */
  get hostCapability(): AuditCapability | undefined {
    return this.#call.hostCapability;
  }

  /**
   * The HTTP request the call is being served under now, where the transport gives one: the request that
   * opened the call, and after each round the retry that resumed it. Undefined on stdio.
   */
  get request(): Request | undefined {
    const request = extraMember(this.#call.extra, 'request');
    return request instanceof Request ? request : undefined;
  }

  /**
   * The authentication information the transport gave with the request the call is being served under
   * now (see {@link request}), as the transport shaped it; undefined where it gave none.
   */
  get authInfo(): unknown {
    return extraMember(this.#call.extra, 'authInfo');
  }

  /**
   * Compare the host's declaration for this call against the tool's, and open the send path (§6.1).
   *
   * A call the host sent without an audit session, or task-augmented, is not negotiated however the
   * declarations compare (§6.2, §6.3, §6.4). Every request of a call is served under the result its first
   * request got, whatever a later one declares (§6.4).
   *
   * @throws {HandshakeNotSeenError} Under §6.5, called before the peer's `initialize` reached the seam.
   * @throws {McpBindingError} `offered` is not what this transport declared on the wire.
   */
  negotiate(offered: AuditCapability): NegotiationResult {
    if (!sameCapability(offered, this.#seam.declares)) {
      throw new McpBindingError('this transport declared a different capability (§6.1)');
    }
    if (!this.#call.modern && !this.#seam.handshakeSeen) {
      throw new HandshakeNotSeenError('the peer has not sent `initialize` yet; negotiate after the handshake (§6.1)');
    }
    const session = this.#call.session;
    if (session?.negotiation !== undefined) {
      this.#call.negotiated = session.negotiation.negotiated;
      return session.negotiation;
    }
    let result = negotiate(this.#call.hostCapability, offered);
    if (result.negotiated && (session === undefined || this.#call.taskAugmented)) {
      result = { ...result, outcome: NegotiationOutcome.NO_SESSION, negotiated: false };
    }
    if (session !== undefined) {
      session.negotiation = result;
    }
    this.#call.negotiated = result.negotiated;
    return result;
  }

  /** Send an attempt and resolve with the host's answer, failing closed on silence (§6, §7.2). */
  async sendAttempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    this.#requireNegotiated();
    return this.#seam._sendAttempt(this.#call, event);
  }

  /** Send an outcome, which has no answer (§6). */
  async sendOutcome(event: Record<string, unknown>): Promise<void> {
    this.#requireNegotiated();
    await this.#seam._sendOutcome(this.#call, event);
  }

  #requireNegotiated(): void {
    if (!this.#call.negotiated) {
      throw new UnnegotiatedSendError(
        'this call is not audit-negotiated, so no audit message may be sent; ' +
          'choose the transport with `transportFor` after `negotiate` (§6.2)',
      );
    }
  }
}

/**
 * The tool side of the wire: it hands out one `McpAuditCall` per `tools/call` (§6.3).
 *
 * A tool is an MCP server, so every declaration passes through this seam. The host's arrives with
 * `initialize` (§6.5) or with each request (§6.4); the tool's goes out in the handshake result. The seam
 * reads the first and writes the second, so what the tool declared on the wire is what it negotiates
 * with - there is no second copy to drift.
 */
export class McpAuditTransport extends FrameSeam {
  readonly declares: AuditCapability;
  /** The instance this seam's round tokens name (§6.4, round affinity). */
  readonly instance: string;
  readonly #requestTimeoutMs: number;
  #handshakeId: string | number | undefined;
  #handshakeSeen = false;
  #handshakeCapability: AuditCapability | undefined;
  /** Calls in flight by their original id, and the rounds out, by token. */
  readonly #calls = new Map<string, ToolCall>();
  /** Sessions no request is serving, least recently idle first (`MAX_IDLE_SESSIONS`). */
  readonly #idle = new Map<string, ToolSession>();
  /**
   * Calls whose handler concluded while a round was out, waiting for its retry, least recently held
   * first (`MAX_IDLE_SESSIONS`), by `idKey` of their original id.
   */
  readonly #concluded = new Map<string, ToolCall>();
  readonly #rounds = new Map<string, ToolCall>();
  /** §6.5 attempts in flight, by the request id this seam gave them. */
  readonly #pending = new Map<string, { pending: Pending; call: ToolCall }>();
  /** The host-issued audit sessions of the requests in flight on this connection, by session id. */
  readonly #sessions = new Map<string, ToolSession>();
  /**
   * Cancelled requests whose handler may still conclude, by `idKey` of their original id. Their final
   * frame is not written; each is forgotten after the request timeout.
   */
  readonly #cancelled = new Map<string, ReturnType<typeof setTimeout>>();

  /**
   * @param options.instance The instance name every round token of this seam carries (§6.4, round
   *   affinity): `[A-Za-z0-9_-]{1,64}`. Defaults to one drawn at random for this process.
   * @throws {McpBindingError} `options.instance` is not a valid instance name.
   */
  constructor(
    inner: McpTransport,
    declares: AuditCapability,
    options: { requestTimeoutMs?: number; instance?: string } = {},
  ) {
    super(inner);
    this.declares = declares;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    const instance = options.instance ?? PROCESS_INSTANCE;
    if (!isInstanceId(instance)) {
      throw new McpBindingError(`${JSON.stringify(instance)} is not an instance name ([A-Za-z0-9_-]{1,64})`);
    }
    this.instance = instance;
  }

  /**
   * True while a call on this connection is running: its handler is running rather than waiting for a
   * round's retry, or an operation the host accepted has not yet emitted its outcome. Closing the
   * connection then would cancel an accepted operation mid-flight, whose outcome could not be known.
   */
  get busy(): boolean {
    for (const call of this.#calls.values()) {
      if (call.cancelled || call.finished) {
        continue;
      }
      if (call.round === undefined || call.accepted.size > 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * True while a call on this connection holds what the host has not yet received: outcomes waiting for
   * the next round, or a final frame kept for a round's retry (§6.4).
   */
  get undelivered(): boolean {
    for (const call of this.#calls.values()) {
      if (call.cancelled) {
        continue;
      }
      if (call.held !== undefined || (call.round !== undefined && call.buffered.length > 0)) {
        return true;
      }
    }
    return false;
  }

  /** True once the peer's `initialize` or `server/discover` has passed through this seam. */
  get handshakeSeen(): boolean {
    return this.#handshakeSeen;
  }

  /**
   * The audit transport for the `tools/call` the MCP handler is serving.
   *
   * The id is matched by JSON type and value, so `1` and `"1"` are two calls. Pass the raw id the request
   * carried (`ctx.mcpReq.id`); a string form cannot name one of two calls whose ids stringify alike, so it
   * is not accepted in place of the raw id.
   *
   * @param requestId The JSON-RPC id of that request, as the request carried it.
   * @throws {UnknownCallError} No `tools/call` with that id is in flight on this connection. When a call
   *   whose id has the same string form is, the message says to pass the raw id.
   */
  call(requestId: string | number | undefined): McpAuditCall {
    const call = this.#calls.get(idKey(requestId));
    if (call === undefined) {
      const alike = [...this.#calls.values()].find((found) => String(found.originalId) === String(requestId));
      const hint =
        alike === undefined
          ? ''
          : `; a call with id ${JSON.stringify(alike.originalId)} is - pass the raw JSON-RPC id ` +
            '(ctx.mcpReq.id), not its string form';
      throw new UnknownCallError(`no tools/call ${JSON.stringify(requestId)} is in flight on this connection${hint}`);
    }
    return new McpAuditCall(this, call);
  }

  /** @internal Carry an attempt in the binding the call uses, and wait, bounded, for the answer. */
  async _sendAttempt(call: ToolCall, event: Record<string, unknown>): Promise<AttemptResponse> {
    if (call.finished || call.cancelled) {
      // No round follows the call's end, so nothing can answer (§6.4).
      return unavailable();
    }
    const pending: Pending = new Once<AttemptResponse>();
    let sent: string | undefined;
    if (call.modern) {
      call.buffered.push(event);
      call.nextAwaiting.set(String(event[fields.ID]), pending);
      this.#scheduleRound(call);
    } else {
      sent = this.newId();
      this.#pending.set(sent, { pending, call });
      try {
        await this.sendFrame({ jsonrpc: '2.0', id: sent, method: ATTEMPT_METHOD, params: event }, call.originalId);
      } catch (error) {
        // A connection that has gone away answers nothing, which is what `unavailable` says.
        console.error(`auditable-mcp: ${ATTEMPT_METHOD} could not be sent; failing closed`, error);
        this.#pending.delete(sent);
        return unavailable();
      }
    }
    const response = await bounded(pending.settled, this.#requestTimeoutMs);
    if (response !== undefined) {
      return response;
    }
    console.error(`auditable-mcp: no answer to an attempt within ${this.#requestTimeoutMs}ms; failing closed`);
    if (sent !== undefined) {
      this.#pending.delete(sent);
    }
    pending.settle(unavailable());
    return unavailable();
  }

  /** @internal Carry an outcome: in the next round or the final result (§6.4), or as a notification (§6.5). */
  async _sendOutcome(call: ToolCall, event: Record<string, unknown>): Promise<void> {
    if (call.cancelled || call.finished) {
      // §6 requires an outcome to go no later than the result; one emitted after it has nowhere to go,
      // and the host records the attempt unresolved (§6.3).
      console.error('auditable-mcp: an outcome was emitted after the call ended; it is lost (§6.3)');
      return;
    }
    if (call.modern) {
      call.buffered.push(event);
      call.accepted.delete(String(event[fields.ID]));
      return;
    }
    try {
      await this.sendFrame({ jsonrpc: '2.0', method: OUTCOME_METHOD, params: event }, call.originalId);
    } catch (error) {
      console.error(`auditable-mcp: ${OUTCOME_METHOD} could not be sent`, error);
    }
  }

  /** End the current round once, after every sibling that is about to emit has emitted (§6.4). */
  #scheduleRound(call: ToolCall): void {
    if (!call.roundScheduled) {
      call.roundScheduled = true;
      // Concurrent operations of one call reach their attempts in the same turn of the event loop;
      // deferring to the next lets them join this round rather than each costing one of its own.
      setTimeout(() => {
        call.roundScheduled = false;
        if (!call.finished && !call.cancelled) {
          void this.#endRound(call);
        }
      }, 0);
    }
  }

  /** Answer the call's current request with an `InputRequiredResult` carrying the buffered events. */
  async #endRound(call: ToolCall): Promise<void> {
    const requestId = call.currentId;
    if (requestId === undefined || call.buffered.length === 0) {
      // A round is out; what is buffered goes with the next one, after its retry.
      return;
    }
    const token = mintRoundToken(this.instance);
    const events = call.buffered;
    call.buffered = [];
    call.round = { token, awaiting: call.nextAwaiting };
    call.nextAwaiting = new Map();
    call.currentId = undefined;
    this.#rounds.set(token, call);
    const result = {
      [RESULT_TYPE]: INPUT_REQUIRED,
      [REQUEST_STATE]: token,
      [META]: { [EXTENSION_ID]: { [fields.SESSION_ID]: call.session?.sessionId, [fields.EVENTS]: events } },
    };
    try {
      await this.sendFrame({ jsonrpc: '2.0', id: requestId, result });
    } catch (error) {
      console.error(`auditable-mcp: a round of tools/call ${String(call.originalId)} could not be sent`, error);
    }
  }

  /** Close the call's open round without a retry: its attempts are unanswered (§6). */
  #closeRound(call: ToolCall): void {
    const round = call.round;
    if (round === undefined) {
      return;
    }
    call.round = undefined;
    this.#rounds.delete(round.token);
    unanswered(round.awaiting);
  }

  /**
   * Take a retry's answers to the round it closes (§6.4), and answer it with the call's final frame if
   * the handler concluded while the round was out. An answer to an attempt already treated as
   * unanswered changes nothing: the first settlement stands.
   */
  async #acceptRetry(call: ToolCall, round: Round, frame: RequestFrame, extra: unknown): Promise<void> {
    call.round = undefined;
    call.extra = extra;
    call.ids.add(idKey(frame.id));
    call.currentId = frame.id;
    const parsed = auditRequestMetaSchema.safeParse(metaOf(frame.params)[EXTENSION_ID]);
    let responses: Record<string, unknown> = {};
    if (!parsed.success || parsed.data.session_id !== call.session?.sessionId) {
      // A retry that does not name this call's session answers none of its attempts, which fails them
      // closed (§6, §6.4).
      console.error(`auditable-mcp: a retry of tools/call ${String(call.originalId)} did not carry its audit session`);
    } else {
      responses = parsed.data.responses ?? {};
    }
    // Only the attempts this round carried: one emitted while it was out goes in the next round.
    for (const [id, pending] of round.awaiting) {
      const response = Object.hasOwn(responses, id) ? readResponse(responses[id], 'a retry') : unavailable();
      // An accept counts as an operation under way only if the handler received it: one that comes after
      // the attempt was already answered `unavailable` starts nothing (§7.2).
      if (pending.settle(response) && response.status === Status.ACCEPT) {
        call.accepted.add(id);
      }
    }
    const held = call.held;
    if (held !== undefined) {
      call.held = undefined;
      this.#concluded.delete(idKey(call.originalId));
      const forward = await this.#conclude(call, held);
      if (forward !== undefined) {
        await this.sendFrame(forward);
      }
      return;
    }
    if (!call.finished && call.buffered.some((event) => event[fields.OUTCOME] === Outcome.ATTEMPTED)) {
      this.#scheduleRound(call);
    }
  }

  protected async inbound(frame: JsonRpcFrame, extra?: unknown): Promise<JsonRpcFrame | undefined> {
    if (isRequest(frame) && (frame.method === INITIALIZE_METHOD || frame.method === DISCOVER_METHOD)) {
      this.#handshakeId = frame.id;
      // `server/discover` carries the peer's capabilities in the request's `_meta`; `initialize` carries
      // them in a `capabilities` member. The declaration inside them is the same object.
      const declared =
        frame.method === DISCOVER_METHOD
          ? metaOf(frame.params)[CLIENT_CAPABILITIES_META_KEY]
          : frame.params?.capabilities;
      this.#handshakeCapability = capabilityOf(declared);
      this.#handshakeSeen = true;
      return frame;
    }
    if (isRequest(frame) && frame.method === TOOLS_CALL_METHOD) {
      return this.#takeCall(frame, extra);
    }
    if (isResponse(frame) && typeof frame.id === 'string' && frame.id.startsWith(ID_PREFIX)) {
      const entry = this.#pending.get(frame.id);
      if (entry === undefined) {
        // An answer to an attempt that is no longer waited for. The id is this seam's, so the session,
        // which never sent it, is not shown it (§6.5).
        console.debug(`auditable-mcp: a late answer to ${frame.id} is dropped`);
        return undefined;
      }
      this.#pending.delete(frame.id);
      if (frame.error !== undefined) {
        // §6 requires a protocol error in place of an Attempt Response to be read as a failure to record.
        console.error(
          `auditable-mcp: ${ATTEMPT_METHOD} ${frame.id} answered with a JSON-RPC error`,
          frame.error.message,
        );
        entry.pending.settle(unavailable());
      } else {
        entry.pending.settle(readResponse(frame.result, ATTEMPT_METHOD));
      }
      return undefined;
    }
    if (isNotification(frame) && frame.method === CANCELLED_METHOD) {
      return this.#cancel(frame);
    }
    return frame;
  }

  /** A new call is tracked and passed on; a retry is taken here and never reaches the session. */
  async #takeCall(frame: RequestFrame, extra: unknown): Promise<JsonRpcFrame | undefined> {
    const params = frame.params ?? {};
    const state = params[REQUEST_STATE];
    if (typeof state === 'string' && state.startsWith(ROUND_TOKEN_PREFIX)) {
      const call = this.#rounds.get(state);
      const round = call?.round;
      this.#rounds.delete(state);
      if (call === undefined || round === undefined || round.token !== state) {
        // Consumed, finished, cancelled, or never issued: a replay the tool must not act on (§6.4).
        await this.sendFrame({
          jsonrpc: '2.0',
          id: frame.id,
          error: { code: INVALID_PARAMS, message: NO_OPEN_ROUND_MESSAGE },
        });
        return undefined;
      }
      await this.#acceptRetry(call, round, frame, extra);
      return undefined;
    }
    const modern = isModern(params);
    const meta = metaOf(params);
    const issued = auditRequestMetaSchema.safeParse(meta[EXTENSION_ID]);
    const declared = modern ? capabilityOf(meta[CLIENT_CAPABILITIES_META_KEY]) : this.#handshakeCapability;
    const session = issued.success ? this.#acquireSession(issued.data.session_id, declared) : undefined;
    this.#forgetCancelled(idKey(frame.id));
    this.#calls.set(idKey(frame.id), {
      originalId: frame.id,
      modern,
      hostCapability: session === undefined ? declared : session.hostCapability,
      session,
      ownSessionId: newSessionId(),
      taskAugmented: isTaskAugmented(params),
      numbering: session?.numbering ?? new SessionNumbering(),
      ids: new Set([idKey(frame.id)]),
      currentId: frame.id,
      negotiated: false,
      buffered: [],
      nextAwaiting: new Map(),
      round: undefined,
      roundScheduled: false,
      finished: false,
      cancelled: false,
      held: undefined,
      accepted: new Set(),
      extra,
    });
    return frame;
  }

  /** The session a request carries: the one its call's first request opened, or a new one (§6.4). */
  #acquireSession(sessionId: string, declared: AuditCapability | undefined): ToolSession {
    let session = this.#sessions.get(sessionId);
    if (session === undefined) {
      session = {
        sessionId,
        hostCapability: declared,
        numbering: new SessionNumbering(),
        negotiation: undefined,
        live: 0,
      };
      this.#sessions.set(sessionId, session);
    }
    this.#idle.delete(sessionId);
    session.live += 1;
    return session;
  }

  #dropSession(session: ToolSession): void {
    if (this.#sessions.get(session.sessionId) === session) {
      this.#sessions.delete(session.sessionId);
      this.#idle.delete(session.sessionId);
    }
  }

  /** Keep a session no request is serving, evicting the least recently idle one beyond the bound. */
  #keepIdle(session: ToolSession): void {
    this.#idle.delete(session.sessionId);
    this.#idle.set(session.sessionId, session);
    for (const evicted of this.#idle.values()) {
      if (this.#idle.size <= MAX_IDLE_SESSIONS) {
        break;
      }
      console.warn(
        `auditable-mcp: more than ${MAX_IDLE_SESSIONS} idle audit sessions; session ${evicted.sessionId} is evicted, ` +
          'and a retry of it will fail closed',
      );
      this.#dropSession(evicted);
    }
  }

  #forgetCancelled(key: string): void {
    const timer = this.#cancelled.get(key);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.#cancelled.delete(key);
    }
  }

  /**
   * Drop a request's state once it is done; its tokens then name no open round (§6.4). `final` is false
   * when the handler answered with its own `input_required`: the call goes on in the client's retry, so
   * its session is kept, idle, until the connection closes or the idle bound evicts it.
   */
  #release(call: ToolCall, final: boolean): void {
    if (this.#calls.get(idKey(call.originalId)) !== call) {
      return;
    }
    this.#calls.delete(idKey(call.originalId));
    this.#concluded.delete(idKey(call.originalId));
    call.held = undefined;
    this.#closeRound(call);
    unanswered(call.nextAwaiting);
    for (const [id, entry] of this.#pending) {
      if (entry.call === call) {
        this.#pending.delete(id);
        entry.pending.settle(unavailable());
      }
    }
    const session = call.session;
    if (session === undefined) {
      return;
    }
    session.live -= 1;
    if (session.live > 0) {
      return;
    }
    if (final) {
      this.#dropSession(session);
    } else {
      this.#keepIdle(session);
    }
  }

  /**
   * The host cancelled a call, naming any id it was served under: its state is dropped, its attempts are
   * unanswered, its rounds close, and whatever its handler still writes is not sent. The cancellation
   * reaches the session under the id the session knows (§6.3) - unless the handler has already finished
   * and only its round was out, when the session has nothing left to cancel.
   */
  #cancel(frame: JsonRpcFrame): JsonRpcFrame | undefined {
    const requestId = frame.params?.requestId;
    const target = idKey(requestId);
    for (const call of this.#calls.values()) {
      if (call.ids.has(target)) {
        call.cancelled = true;
        this.#release(call, true);
        if (call.finished) {
          return undefined;
        }
        const original = idKey(call.originalId);
        this.#forgetCancelled(original);
        this.#cancelled.set(
          original,
          after(this.#requestTimeoutMs, () => this.#cancelled.delete(original)),
        );
        return target === original ? frame : { ...frame, params: { ...frame.params, requestId: call.originalId } };
      }
    }
    return frame;
  }

  /** Declare on the handshake result, and put a call's final result on the id that is still open. */
  protected override async outbound(frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    if (isResponse(frame) && frame.id === this.#handshakeId && frame.result !== undefined) {
      const capabilities: WithExtensions = { ...((frame.result.capabilities as WithExtensions) ?? {}) };
      declareInto(capabilities, this.declares);
      return { ...frame, result: { ...frame.result, capabilities } };
    }
    if (isResponse(frame) && this.#cancelled.has(idKey(frame.id))) {
      this.#forgetCancelled(idKey(frame.id));
      console.debug(`auditable-mcp: tools/call ${String(frame.id)} was cancelled; its final frame is not written`);
      return undefined;
    }
    if (isResponse(frame)) {
      const call = this.#calls.get(idKey(frame.id));
      if (call !== undefined && call.originalId === frame.id && !call.finished) {
        call.finished = true;
        const continues = frame.result?.[RESULT_TYPE] === INPUT_REQUIRED;
        const state = frame.result?.[REQUEST_STATE];
        if (continues && typeof state === 'string' && state.startsWith(ROUND_TOKEN_PREFIX)) {
          console.error(
            `auditable-mcp: tools/call ${String(frame.id)} answered with its own requestState under the reserved ` +
              `prefix "${ROUND_TOKEN_PREFIX}"; its retry will be refused as a replay (§6.4)`,
          );
        }
        if (!call.modern) {
          this.#release(call, !continues);
          return frame;
        }
        return this.#finish(call, frame);
      }
    }
    return frame;
  }

  /**
   * Deliver the call's remaining outcomes no later than its result, on the id still open (§6, §6.4).
   *
   * A handler can conclude while a round is out - an attempt timed out, or it stopped waiting. The final
   * frame and the outcomes are then kept until that round's retry, however late, and go out on its id.
   * Nothing but the connection's end, a cancellation, or the bound on kept calls drops them.
   */
  async #finish(call: ToolCall, frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    // A final result carries no attempt (§6.4). One still unsent was abandoned by the handler.
    if (call.buffered.some((event) => event[fields.OUTCOME] === Outcome.ATTEMPTED)) {
      console.error(`auditable-mcp: tools/call ${String(call.originalId)} ended with an attempt it never sent`);
      call.buffered = call.buffered.filter((event) => event[fields.OUTCOME] !== Outcome.ATTEMPTED);
    }
    unanswered(call.nextAwaiting);
    if (call.round !== undefined) {
      this.#keepConcluded(call, frame);
      return undefined;
    }
    return this.#conclude(call, frame);
  }

  /**
   * Answer the open id with the call's final frame and release the call. A JSON-RPC error has no `_meta`
   * to carry outcomes in, so outcomes still buffered go in a round of their own first, and the error is
   * kept for that round's retry (§6.4).
   */
  async #conclude(call: ToolCall, frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    const outcomes = call.buffered;
    call.buffered = [];
    if (frame.error !== undefined && outcomes.length > 0) {
      call.buffered = outcomes;
      await this.#endRound(call);
      this.#keepConcluded(call, frame);
      return undefined;
    }
    const forward = this.#onOpenId(call, frame);
    this.#release(call, frame.result?.[RESULT_TYPE] !== INPUT_REQUIRED);
    if (forward === undefined || frame.error !== undefined || outcomes.length === 0) {
      return forward;
    }
    const result = { ...(forward.result ?? {}) };
    result[META] = {
      ...metaOf(result),
      [EXTENSION_ID]: { [fields.SESSION_ID]: call.session?.sessionId, [fields.EVENTS]: outcomes },
    };
    return { ...forward, result };
  }

  /** Keep a concluded call for its round's retry, evicting the least recently kept one beyond the bound. */
  #keepConcluded(call: ToolCall, frame: JsonRpcFrame): void {
    const key = idKey(call.originalId);
    call.held = frame;
    this.#concluded.delete(key);
    this.#concluded.set(key, call);
    for (const evicted of this.#concluded.values()) {
      if (this.#concluded.size <= MAX_IDLE_SESSIONS) {
        break;
      }
      console.warn(
        `auditable-mcp: more than ${MAX_IDLE_SESSIONS} concluded calls await a retry; tools/call ` +
          `${String(evicted.originalId)} (session ${evicted.session?.sessionId ?? evicted.ownSessionId}) is ` +
          'dropped, and its final frame and outcomes are not sent',
      );
      evicted.cancelled = true;
      this.#release(evicted, true);
    }
  }

  /** Put the frame on the id the host is waiting on; none is open while a round is out. */
  #onOpenId(call: ToolCall, frame: JsonRpcFrame): JsonRpcFrame | undefined {
    return call.currentId === undefined ? undefined : { ...frame, id: call.currentId };
  }

  protected override async onConnectionLost(): Promise<void> {
    // A closed connection will not answer, and a tool left waiting would neither record nor abort.
    for (const call of [...this.#calls.values()]) {
      call.cancelled = true;
      this.#release(call, true);
    }
    for (const entry of this.#pending.values()) {
      entry.pending.settle(unavailable());
    }
    this.#pending.clear();
    for (const session of [...this.#sessions.values()]) {
      this.#dropSession(session);
    }
    for (const key of [...this.#cancelled.keys()]) {
      this.#forgetCancelled(key);
    }
  }
}

/** A `tools/call` this host sent, and the audit session it issued for it (§6.3). */
interface HostCall {
  readonly originalId: string | number;
  readonly params: Record<string, unknown>;
  readonly sessionId: string;
  /** The id the client last sent for this call; its final answer goes out on it. */
  clientId: string | number;
  /** The id the tool answers on: the client's, or a retry this seam sent. */
  currentId: string | number;
  rounds: number;
  /**
   * A round that also asked the client for input goes up to the session; its responses wait here for the
   * client's retry, found by the round's `requestState`.
   */
  held: { readonly state: string; readonly responses: Record<string, unknown> } | undefined;
  /**
   * The request metadata headers of the request the tool is answering - the client's, as its session
   * sent them - which each retry repeats, since a retry is the same request (§6.4, round affinity).
   */
  headers: Readonly<Record<string, string>> | undefined;
  /** The signal that cancels the client's request, which a retry carries too, so cancelling reaches it. */
  requestSignal: AbortSignal | undefined;
  /** The call has ended: nothing more is done for it, and a response for it is dropped (§6.3). */
  ended: boolean;
  /** Its session has been closed at the endpoint. */
  closed: boolean;
}

/**
 * The expected session the seam gives the endpoint for an event that arrived on no call in flight. It
 * names no session, so the endpoint refuses the event as not the call's (§6.3).
 */
const NO_CALL_IN_FLIGHT = '';

/** What a round's deadline resolves to, so a race can tell it from a decision. */
const DEADLINE: unique symbol = Symbol('deadline');

/**
 * A result as the client should see it: without this extension's member, and without a `_meta` that it
 * leaves empty (§6.4). The events are the host's audit input, not part of the tool's answer.
 */
function withoutAudit(frame: JsonRpcFrame): JsonRpcFrame {
  const meta = frame.result?.[META];
  if (!isObject(meta) || !Object.hasOwn(meta, EXTENSION_ID)) {
    return frame;
  }
  const { [EXTENSION_ID]: _audit, ...rest } = meta;
  const { [META]: _meta, ...result } = frame.result as Record<string, unknown>;
  return { ...frame, result: Object.keys(rest).length === 0 ? result : { ...result, [META]: rest } };
}

const ROUND_LIMIT_MESSAGE = `the tool exceeded the limit of ${MAX_ROUNDS_PER_CALL} audit rounds for one call`;
const NO_REQUEST_STATE_MESSAGE = 'the tool asked for input without a requestState (§6.4)';
const RETRY_NOT_SENT_MESSAGE = 'the retry of an audit round could not be sent (§6.4)';

/**
 * The host side of the wire: issues sessions, answers attempts, seals outcomes (§6, §7).
 *
 * A host is an MCP client. Its declaration goes out on the handshake (§6.5) and on every request that
 * carries the client's capabilities (§6.4), and it is `endpoint.capability` - the requirement the
 * endpoint enforces at runtime (§7) and the one it declares are the same object.
 *
 * Audit work is queued per audit session, not per connection: the work of one session - its events, the
 * call's responses, and closing the session - runs in arrival order, and a slow decision in one session
 * holds up neither another session nor the connection's other traffic.
 */
export class McpAuditReceiver extends FrameSeam {
  readonly #endpoint: AuditEndpoint;
  /** Calls in flight by the id the tool currently answers on, and by their audit session. */
  readonly #calls = new Map<string, HostCall>();
  readonly #bySession = new Map<string, HostCall>();
  /** Every call whose session is not yet closed, in flight or concluding, by its audit session. */
  readonly #unclosed = new Map<string, HostCall>();
  /**
   * Rounds passed up to the client and awaiting its retry, by `requestState`, least recently held first
   * (`MAX_IDLE_SESSIONS`).
   */
  readonly #held = new Map<string, HostCall>();
  /** The tail of each audit session's queue, while it has work. */
  readonly #chains = new Map<string, Promise<void>>();
  /**
   * Ids a cancelled call may still be answered on, by `idKey`; the answer is dropped (§6.3). Each is
   * forgotten after the request timeout.
   */
  readonly #endedIds = new Map<string, ReturnType<typeof setTimeout>>();
  /** The handshake request whose result carries the tool's declaration, until that result is read. */
  #handshakeId: string | undefined;
  #handshakeRead = false;
  readonly #requestTimeoutMs: number;

  /**
   * @param options.requestTimeoutMs The bound on the audit work a response waits for: a §6.5 attempt's
   *   decision, one §6.4 round's processing, and closing the sessions when the connection ends.
   */
  constructor(inner: McpTransport, endpoint: AuditEndpoint, options: { requestTimeoutMs?: number } = {}) {
    super(inner);
    this.#endpoint = endpoint;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  /** Declare this host on the way out, and issue an audit session for each `tools/call` (§6.3). */
  protected override async outbound(frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    if (isNotification(frame) && frame.method === CANCELLED_METHOD) {
      return this.#cancel(frame);
    }
    if (
      isRequest(frame) &&
      (frame.method === INITIALIZE_METHOD || frame.method === DISCOVER_METHOD) &&
      !this.#handshakeRead
    ) {
      this.#handshakeId = idKey(frame.id);
    }
    if (!isRequest(frame) || frame.params === undefined) {
      return frame;
    }
    if (frame.method === TOOLS_CALL_METHOD && frame.params[META] !== undefined && !isObject(frame.params[META])) {
      // A `_meta` that is not an object has nowhere to carry a session, so the call goes as it is, unaudited.
      return frame;
    }
    const params = this.#declared(frame.method, frame.params);
    if (frame.method !== TOOLS_CALL_METHOD) {
      return { ...frame, params };
    }
    const state = params[REQUEST_STATE];
    const held = typeof state === 'string' ? this.#held.get(state) : undefined;
    if (held?.held !== undefined) {
      // The client's own retry of a round that asked it for input: the answers ride along (§6.4). It
      // belongs to a call already audited, so the task check below, which is for new calls, does not apply.
      const { responses } = held.held;
      this.#unhold(held);
      this.#calls.delete(idKey(held.currentId));
      held.clientId = frame.id;
      held.currentId = frame.id;
      this.#calls.set(idKey(frame.id), held);
      const meta = {
        ...metaOf(params),
        [EXTENSION_ID]: { [fields.SESSION_ID]: held.sessionId, [fields.RESPONSES]: responses },
      };
      return { ...frame, params: { ...params, [META]: meta } };
    }
    if (isTaskAugmented(params)) {
      // This version binds no task-augmented call (§6.4), so the host does not ask to audit one.
      return { ...frame, params };
    }
    const sessionId = this.#endpoint.openSession();
    const meta = { ...metaOf(params), [EXTENSION_ID]: { [fields.SESSION_ID]: sessionId } };
    const issued = { ...params, [META]: meta };
    const call: HostCall = {
      originalId: frame.id,
      params: structuredClone(issued),
      sessionId,
      clientId: frame.id,
      currentId: frame.id,
      rounds: 0,
      held: undefined,
      headers: undefined,
      requestSignal: undefined,
      ended: false,
      closed: false,
    };
    this.#calls.set(idKey(frame.id), call);
    this.#bySession.set(sessionId, call);
    this.#unclosed.set(sessionId, call);
    return { ...frame, params: issued };
  }

  /**
   * Carry the audit session in the headers of a call's request (§6.4, round affinity), and keep what the
   * client's request carried for the retries that repeat it. The opening request and the client's own
   * retries keep the client's headers and get the affinity header added.
   */
  protected override outboundOptions(frame: JsonRpcFrame, options: unknown): unknown {
    if (!isRequest(frame) || frame.method !== TOOLS_CALL_METHOD) {
      return options;
    }
    const call = this.#calls.get(idKey(frame.id));
    if (call === undefined || call.ended || idKey(call.clientId) !== idKey(frame.id)) {
      return options;
    }
    const carried = perRequestOf(options);
    call.headers = carried.headers;
    this.#watch(call, carried.requestSignal);
    return { ...(isObject(options) ? options : {}), headers: withAffinityHeader(carried.headers, call.sessionId) };
  }

  /** The send options of a retry this seam sends: the repeated request's headers, and its cancellation. */
  #retryOptions(call: HostCall): Record<string, unknown> {
    return {
      headers: withAffinityHeader(call.headers, call.sessionId),
      ...(call.requestSignal === undefined ? {} : { requestSignal: call.requestSignal }),
    };
  }

  /**
   * On a per-request-stream transport the session cancels a request by aborting its signal rather than by
   * sending `notifications/cancelled`; the call then ends as a cancelled one does (§6.3).
   */
  #watch(call: HostCall, signal: AbortSignal | undefined): void {
    call.requestSignal = signal;
    if (signal === undefined) {
      return;
    }
    const abandon = (): void => {
      if (call.requestSignal !== signal || !this.#detach(call)) {
        return;
      }
      this.#dropLater(call.currentId);
      void this.#inSession(call.sessionId, () => this.#close(call));
    };
    if (signal.aborted) {
      abandon();
    } else {
      signal.addEventListener('abort', abandon, { once: true });
    }
  }

  /**
   * Hold a round's responses for the client's retry, evicting the least recently held round beyond the
   * bound. An evicted call ends: its session closes, and a retry of it is a new call.
   */
  #hold(call: HostCall, state: string, responses: Record<string, unknown>): void {
    const previous = this.#held.get(state);
    if (previous !== undefined && previous !== call) {
      this.#evict(previous, `another call's round was held under the same requestState`);
    }
    this.#unhold(call);
    call.held = { state, responses };
    this.#held.set(state, call);
    for (const evicted of this.#held.values()) {
      if (this.#held.size <= MAX_IDLE_SESSIONS) {
        break;
      }
      this.#evict(evicted, `more than ${MAX_IDLE_SESSIONS} rounds await the client's retry`);
    }
  }

  #unhold(call: HostCall): void {
    if (call.held !== undefined && this.#held.get(call.held.state) === call) {
      this.#held.delete(call.held.state);
    }
    call.held = undefined;
  }

  #evict(call: HostCall, why: string): void {
    console.warn(
      `auditable-mcp: ${why}; tools/call ${String(call.originalId)} (session ${call.sessionId}) is ended, ` +
        'and a retry of it will be a new call',
    );
    if (this.#detach(call)) {
      void this.#inSession(call.sessionId, () => this.#close(call));
    }
  }

  /**
   * Warn when the tool's handshake declaration does not meet this host's requirement (§6.1, §6.2).
   *
   * The binding cannot refuse the connection for the host: whether an unaudited tool may be called is
   * the host's decision, made on `capabilityOf(client.getServerCapabilities())`. What the binding owes it
   * is that the fact is not silent, since every call the tool makes is otherwise unaudited.
   */
  #checkDeclaration(capabilities: unknown): void {
    const declared = capabilityOf(capabilities);
    if (declared === undefined) {
      console.warn(
        `auditable-mcp: the tool declared no auditable-mcp capability in the handshake (outcome ${NegotiationOutcome.UNDECLARED}); its calls are not audited`,
      );
      return;
    }
    const fit = negotiate(this.#endpoint.capability, declared);
    if (!fit.negotiated) {
      console.warn(
        `auditable-mcp: the tool declared ${JSON.stringify(declared)}, which does not meet this host's requirement ` +
          `${JSON.stringify(this.#endpoint.capability)} (outcome ${fit.outcome}: versionMatch=${fit.versionMatch} ` +
          `levelFit=${fit.levelFit} countersignFit=${fit.countersignFit}); its calls are not audited`,
      );
    }
  }

  /** Write the host's declaration wherever this request carries the client's capabilities (§6.1). */
  #declared(method: string, params: Record<string, unknown>): Record<string, unknown> {
    if (method === INITIALIZE_METHOD) {
      const capabilities: WithExtensions = { ...((params.capabilities as WithExtensions) ?? {}) };
      declareInto(capabilities, this.#endpoint.capability);
      return { ...params, capabilities };
    }
    const meta = metaOf(params);
    const carried = meta[CLIENT_CAPABILITIES_META_KEY];
    if (carried === null || typeof carried !== 'object') {
      return params;
    }
    const capabilities: WithExtensions = { ...(carried as WithExtensions) };
    declareInto(capabilities, this.#endpoint.capability);
    return { ...params, [META]: { ...meta, [CLIENT_CAPABILITIES_META_KEY]: capabilities } };
  }

  /**
   * A cancelled call ends, and its session closes behind the audit work already queued for it, so what
   * arrived before the cancellation is decided against a session still open (§6.3). The cancellation
   * goes to the id the tool answers on.
   */
  #cancel(frame: JsonRpcFrame): JsonRpcFrame {
    const requestId = frame.params?.requestId;
    for (const call of this.#calls.values()) {
      if (idKey(call.clientId) === idKey(requestId)) {
        const target = call.currentId;
        this.#detach(call);
        this.#dropLater(target);
        void this.#inSession(call.sessionId, () => this.#close(call));
        return idKey(target) === idKey(requestId)
          ? frame
          : { ...frame, params: { ...frame.params, requestId: target } };
      }
    }
    return frame;
  }

  /** The call an inbound request is related to, where the transport says so. */
  #relatedCall(extra: unknown): HostCall | undefined {
    if (extra === null || typeof extra !== 'object') {
      return undefined;
    }
    const related = (extra as { relatedRequestId?: unknown }).relatedRequestId;
    return typeof related === 'string' || typeof related === 'number' ? this.#calls.get(idKey(related)) : undefined;
  }

  /**
   * The audit session an event arrived on (§6.5): the related call's, where the transport relates
   * requests; otherwise the event's own, if this host issued it for a call in flight on this connection.
   * Read when the event arrives, not when its turn in the queue comes.
   */
  #expectedSession(event: Record<string, unknown>, extra: unknown): string {
    const related = this.#relatedCall(extra);
    if (related !== undefined) {
      return related.sessionId;
    }
    const sessionId = event[fields.SESSION_ID];
    return typeof sessionId === 'string' && this.#bySession.has(sessionId) ? sessionId : NO_CALL_IN_FLIGHT;
  }

  /** Queue `job` behind the audit work already queued for the session (§6). Never rejects. */
  #inSession(sessionId: string, job: () => Promise<void>): Promise<void> {
    const next = (this.#chains.get(sessionId) ?? Promise.resolve()).then(job).catch((error: unknown) => {
      console.error('auditable-mcp: the audit binding could not complete work for a session', error);
    });
    this.#chains.set(sessionId, next);
    void next.then(() => {
      if (this.#chains.get(sessionId) === next) {
        this.#chains.delete(sessionId);
      }
    });
    return next;
  }

  protected override enqueue(message: JsonRpcFrame, extra?: unknown): void {
    if (message.method === ATTEMPT_METHOD && isRequest(message)) {
      const event = message.params ?? {};
      const sessionId = this.#expectedSession(event, extra);
      void this.#inSession(sessionId, async () => {
        const response = await this.#decide(event, sessionId);
        await this.sendFrame({ jsonrpc: '2.0', id: message.id, result: response });
      });
      return;
    }
    if (message.method === OUTCOME_METHOD && isNotification(message)) {
      const event = message.params ?? {};
      const sessionId = this.#expectedSession(event, extra);
      void this.#inSession(sessionId, () => this.#sealOutcome(event, sessionId));
      return;
    }
    if (isResponse(message)) {
      const call = this.#calls.get(idKey(message.id));
      if (call !== undefined && call.currentId === message.id && concludes(message) && this.#detach(call)) {
        // The call's answer reaches the client at once. Sealing what it carries and closing the session
        // follow in the session's queue, behind the audit work already there: the session ends when that
        // is done (§6.3), but the client does not wait on the host's audit.
        const result = message.result;
        void this.#inSession(call.sessionId, async () => {
          if (message.error === undefined && result !== undefined) {
            for (const event of this.#eventsOf(result, call)) {
              // A final result carries outcomes only; an attempt in it is refused as one (§6.4).
              await this.#sealOutcome(event, call.sessionId);
            }
          }
          await this.#close(call);
        });
        this.deliver(withoutAudit({ ...message, id: call.clientId }), extra);
        return;
      }
      if (call !== undefined && call.currentId === message.id) {
        void this.#inSession(call.sessionId, async () => {
          const forward = await this.#follow(call, message);
          if (forward !== undefined) {
            this.deliver(forward, extra);
          }
        });
        return;
      }
      const ended = this.#endedIds.get(idKey(message.id));
      if (ended !== undefined) {
        clearTimeout(ended);
        this.#endedIds.delete(idKey(message.id));
        console.debug(`auditable-mcp: a response for the ended tools/call ${String(message.id)} is dropped`);
        return;
      }
    }
    void this.receive(message, extra);
  }

  protected async inbound(frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    if (isResponse(frame) && this.#handshakeId !== undefined && idKey(frame.id) === this.#handshakeId) {
      this.#handshakeId = undefined;
      this.#handshakeRead = true;
      this.#checkDeclaration(frame.result?.capabilities);
      return frame;
    }
    if (frame.method === OUTCOME_METHOD && isRequest(frame)) {
      // §6.5 defines the outcome as a notification. One sent as a request is a malformed envelope, which
      // is what a JSON-RPC error is for, and it is not sealed either way.
      await this.sendFrame({
        jsonrpc: '2.0',
        id: frame.id,
        error: { code: INVALID_REQUEST, message: `${OUTCOME_METHOD} is a notification (§6.5)` },
      });
      return undefined;
    }
    if (frame.method === ATTEMPT_METHOD && isNotification(frame)) {
      // An attempt without an id has no response channel, so it cannot be accepted and the tool cannot be
      // told. Sealing it would record an operation the tool never learned was cleared.
      console.error(`auditable-mcp: ${ATTEMPT_METHOD} arrived as a notification; it cannot be answered`);
      return undefined;
    }
    return frame;
  }

  /** Seal what a call's response carries; retry a round that asks for nothing else, end the rest. */
  async #follow(call: HostCall, frame: JsonRpcFrame): Promise<JsonRpcFrame | undefined> {
    if (call.ended) {
      // Cancelled, or the connection closed, after this response arrived (§6.3).
      return undefined;
    }
    if (frame.error !== undefined) {
      await this.#end(call);
      return { ...frame, id: call.clientId };
    }
    const result = frame.result ?? {};
    const events = this.#eventsOf(result, call);
    if (result[RESULT_TYPE] !== INPUT_REQUIRED) {
      for (const event of events) {
        // A final result carries outcomes only; an attempt in it is refused as one (§6.4).
        await this.#sealOutcome(event, call.sessionId);
      }
      if (call.ended) {
        return undefined;
      }
      await this.#end(call);
      return withoutAudit({ ...frame, id: call.clientId });
    }
    call.rounds += 1;
    const state = result[REQUEST_STATE];
    if (call.rounds > MAX_ROUNDS_PER_CALL || typeof state !== 'string') {
      // No retry follows, so the session ends here (§6.4). The round's outcomes are sealed before it does;
      // its attempts are not decided, since no retry would carry the answers.
      const { rest } = await this.#processRound(call, events, false);
      if (call.ended) {
        await rest?.();
        return undefined;
      }
      const message = typeof state === 'string' ? ROUND_LIMIT_MESSAGE : NO_REQUEST_STATE_MESSAGE;
      console.error(`auditable-mcp: tools/call ${String(call.originalId)}: ${message}`);
      this.#detach(call);
      void this.#inSession(call.sessionId, async () => {
        await rest?.();
        await this.#close(call);
      });
      return { jsonrpc: '2.0', id: call.clientId, error: { code: INTERNAL_ERROR, message } };
    }
    const { responses, rest } = await this.#processRound(call, events, true);
    if (call.ended) {
      // Cancelled while the round was being decided: there is no retry and nothing to answer. What the
      // deadline cut off finishes here, ahead of the session's close, which is queued behind this.
      await rest?.();
      return undefined;
    }
    if (rest !== undefined) {
      // Queued before the retry goes, so it stays ahead of anything the retry's answer brings (§6).
      void this.#inSession(call.sessionId, rest);
    }
    const inputRequests = result[INPUT_REQUESTS];
    if (inputRequests !== undefined && inputRequests !== null && Object.keys(inputRequests).length > 0) {
      // The round also asks the client for input, which only the client can give. It goes up; the
      // answers ride on the client's retry.
      this.#hold(call, state, responses);
      return withoutAudit({ ...frame, id: call.clientId });
    }
    // A round that asks for nothing but the audit answers is retried here, at once (§6.4).
    this.#calls.delete(idKey(call.currentId));
    const retryId = this.newId();
    call.currentId = retryId;
    this.#calls.set(idKey(retryId), call);
    const params: Record<string, unknown> = structuredClone(call.params);
    params[REQUEST_STATE] = state;
    params[META] = {
      ...metaOf(params),
      [EXTENSION_ID]: { [fields.SESSION_ID]: call.sessionId, [fields.RESPONSES]: responses },
    };
    try {
      await this.inner.send(
        { jsonrpc: '2.0', id: retryId, method: TOOLS_CALL_METHOD, params },
        this.#retryOptions(call),
      );
    } catch (error) {
      if (call.ended) {
        // Cancelled while the retry was being sent: nothing is left to answer.
        return undefined;
      }
      console.error(`auditable-mcp: the retry of tools/call ${String(call.originalId)} could not be sent`, error);
      await this.#end(call);
      return { jsonrpc: '2.0', id: call.clientId, error: { code: INTERNAL_ERROR, message: RETRY_NOT_SENT_MESSAGE } };
    }
    return undefined;
  }

  /**
   * Process a round's events in array order, one at a time, under one deadline (§6.4).
   *
   * The tool can answer its caller only on the retry, so the retry is not held past the deadline for the
   * audit subsystem. An attempt reached after it is answered `unavailable` without reaching the endpoint;
   * one being decided when it passes is answered `unavailable` and its decision goes on in the
   * background, where it is not undone, and the tool, told `unavailable`, does not act (§7.2). The work
   * the deadline cut off - that decision or an outcome being sealed, then the outcomes after it - is
   * returned as `rest`, for the session's queue, so it stays in order ahead of the next round.
   *
   * @param decide False when no retry will carry answers: the attempts are left undecided.
   */
  async #processRound(
    call: HostCall,
    events: unknown[],
    decide: boolean,
  ): Promise<{ responses: Record<string, unknown>; rest: (() => Promise<void>) | undefined }> {
    const responses: Record<string, unknown> = {};
    let timer: ReturnType<typeof setTimeout> | undefined;
    let expired = false;
    const dueAt = Date.now() + this.#requestTimeoutMs;
    const deadline = new Promise<typeof DEADLINE>((resolve) => {
      timer = setTimeout(() => {
        expired = true;
        resolve(DEADLINE);
      }, this.#requestTimeoutMs);
    });
    // An outcome being sealed at the deadline: the outcomes after it are sealed behind it, in order.
    let inProgress: Promise<unknown> | undefined;
    let cutOff = false;
    let index = 0;
    try {
      for (; index < events.length && !expired; index += 1) {
        const event = events[index];
        if (isAnswerableAttempt(event)) {
          if (!decide) {
            continue;
          }
          const decision = this.#decision(event, call.sessionId, dueAt);
          const decided = await Promise.race([decision, deadline]);
          if (decided === DEADLINE) {
            // The decision goes on outside the session's queue, as the endpoint is not interrupted
            // mid-seal; what follows it in the round does not wait on it. Taken up after the deadline, it
            // records nothing (AuditEndpoint.handleAttempt).
            responses[event[fields.ID]] = unavailable();
            index += 1;
            break;
          }
          responses[event[fields.ID]] = decided;
        } else {
          const sealing = this.#sealOutcome(event, call.sessionId);
          if ((await Promise.race([sealing, deadline])) === DEADLINE) {
            inProgress = sealing;
            index += 1;
            break;
          }
        }
      }
    } finally {
      clearTimeout(timer);
    }
    cutOff = expired;
    const remaining = events.slice(index);
    if (!cutOff && remaining.length === 0) {
      return { responses, rest: undefined };
    }
    let undecided = 0;
    for (const event of remaining) {
      if (decide && isAnswerableAttempt(event)) {
        responses[event[fields.ID]] = unavailable();
        undecided += 1;
      }
    }
    const outcomes = remaining.filter((event) => !isAnswerableAttempt(event));
    console.warn(
      `auditable-mcp: a round of tools/call ${String(call.originalId)} (session ${call.sessionId}) was not ` +
        `processed within ${this.#requestTimeoutMs}ms; ${undecided} further attempt(s) are answered unavailable ` +
        `undecided, and ${outcomes.length} outcome(s) are sealed after the call goes on`,
    );
    return {
      responses,
      rest: async () => {
        await inProgress;
        for (const event of outcomes) {
          await this.#sealOutcome(event, call.sessionId);
        }
      },
    };
  }

  /** The events a result carries for this call's session, in the order the tool emitted them. */
  #eventsOf(result: Record<string, unknown>, call: HostCall): unknown[] {
    const carried = metaOf(result)[EXTENSION_ID] as Record<string, unknown> | undefined;
    if (carried === undefined || carried === null || typeof carried !== 'object') {
      return [];
    }
    const events = carried[fields.EVENTS];
    if (!Array.isArray(events)) {
      console.error(`auditable-mcp: tools/call ${String(call.originalId)} carried an audit _meta without events`);
      return [];
    }
    // Every item is handed on, valid or not: one that is not a valid event is refused alone, never
    // dropped (§6.4).
    return events;
  }

  /** Take the call out of flight; false if it had already ended. */
  #detach(call: HostCall): boolean {
    if (call.ended) {
      return false;
    }
    call.ended = true;
    this.#unhold(call);
    if (this.#calls.get(idKey(call.currentId)) === call) {
      this.#calls.delete(idKey(call.currentId));
    }
    if (this.#bySession.get(call.sessionId) === call) {
      this.#bySession.delete(call.sessionId);
    }
    return true;
  }

  /** Drop the tool's answer on `id` if one still comes, for as long as the request timeout. */
  #dropLater(id: string | number): void {
    const key = idKey(id);
    clearTimeout(this.#endedIds.get(key));
    this.#endedIds.set(
      key,
      after(this.#requestTimeoutMs, () => this.#endedIds.delete(key)),
    );
  }

  /** The call ended, from within its session's queue: its session closes now (§6.3). */
  async #end(call: HostCall): Promise<void> {
    if (this.#detach(call)) {
      await this.#close(call);
    }
  }

  /** Close the call's session once; the endpoint records any attempt left unresolved (§6.3). */
  async #close(call: HostCall): Promise<void> {
    if (call.closed) {
      return;
    }
    call.closed = true;
    try {
      await this.#endpoint.closeSession(call.sessionId);
    } finally {
      this.#unclosed.delete(call.sessionId);
    }
  }

  /**
   * Hand an attempt to the endpoint, bounded, turning a throw or a late decision into `unavailable`.
   *
   * The wait is bounded because the tool's answer to its caller waits on it: under §6.4 the tool can reply
   * only on the retry this decision releases, so an endpoint that stalls would hold the call's result for as
   * long as it stalls, and past the tool's own bound the result is lost. A decision that arrives late still
   * completes - the endpoint is not interrupted mid-seal - and the tool, told `unavailable`, does not act
   * (§7.2); the record it leaves is concluded by the tool's abort.
   */
  async #decide(event: Record<string, unknown>, sessionId: string): Promise<AttemptResponse> {
    const decided = await bounded(
      this.#decision(event, sessionId, Date.now() + this.#requestTimeoutMs),
      this.#requestTimeoutMs,
    );
    if (decided !== undefined) {
      return decided;
    }
    console.warn(
      `auditable-mcp: the audit endpoint did not decide an attempt within ${this.#requestTimeoutMs}ms; answering unavailable`,
    );
    return unavailable();
  }

  /** The endpoint's decision on an attempt, with a throw turned into `unavailable`. Never rejects. */
  #decision(event: Record<string, unknown>, sessionId: string, deadline: number): Promise<AttemptResponse> {
    return this.#endpoint.handleAttempt(event, sessionId, deadline).catch((error: unknown) => {
      // §6 requires every audit-layer decision to travel as an Attempt Response, never as an error, so an
      // endpoint that threw has to be turned into one. It recorded nothing, which is what `unavailable`
      // says, and the tool already fails closed on it (§7.2).
      console.error('auditable-mcp: the audit endpoint threw while deciding an attempt', error);
      return unavailable();
    });
  }

  /** Hand an outcome to the endpoint. It has no response (§6). Never rejects. */
  async #sealOutcome(event: unknown, sessionId: string): Promise<void> {
    try {
      await this.#endpoint.handleOutcome(event, sessionId);
    } catch (error) {
      // There is no channel to answer on, so the endpoint's own anomaly set is where this belongs (§7.6).
      console.error('auditable-mcp: the audit endpoint threw while sealing an outcome', error);
    }
  }

  /**
   * The connection ended, so every call still open on it has ended too (§6.3). Each session - of a call in
   * flight or of one concluding - closes behind the audit work that arrived before the connection went.
   * The whole is bounded by the request timeout: work still queued then is reported by session, and
   * every session is closed regardless.
   */
  protected override async onConnectionLost(): Promise<void> {
    const deadline = Date.now() + this.#requestTimeoutMs;
    for (const call of [...this.#bySession.values()]) {
      this.#detach(call);
      void this.#inSession(call.sessionId, () => this.#close(call));
    }
    this.#calls.clear();
    await bounded(Promise.all([...this.#chains.values()]), this.#requestTimeoutMs);
    for (const sessionId of this.#chains.keys()) {
      console.warn(
        `auditable-mcp: the connection closed and audit work for session ${sessionId} was still queued after ` +
          `${this.#requestTimeoutMs}ms; the session is closed regardless`,
      );
    }
    const closing = [...this.#unclosed.values()].map((call) => this.#close(call));
    await bounded(Promise.allSettled(closing), Math.max(0, deadline - Date.now()));
    for (const sessionId of this.#unclosed.keys()) {
      console.warn(`auditable-mcp: the connection closed and session ${sessionId} did not close in time`);
    }
    for (const timer of this.#endedIds.values()) {
      clearTimeout(timer);
    }
    this.#endedIds.clear();
  }
}
