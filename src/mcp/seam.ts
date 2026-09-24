/**
 * Carrying `audit/attempt` and `audit/outcome` on an MCP connection (§6).
 *
 * Neither official MCP SDK can deliver these methods through its own dispatch: a session parses each
 * incoming message into a fixed request union and answers anything outside it before a handler is
 * consulted, and the Python client registers no request handlers at all. Nothing about the audit wire
 * needs that dispatch, though — it is ordinary JSON-RPC on the connection MCP already holds — so this
 * binding sits one layer lower, between the session and the transport.
 *
 * A `Transport` is something the integrator hands to the session, so each side wraps the real one and
 * hands the session a seam instead. Audit frames are taken out of the inbound flow and answered here;
 * every other message passes through untouched, in order, so the session sees exactly the MCP it
 * would have seen without this extension. The two roles are separate classes because the obligations
 * are: a tool cannot be made to seal an attempt, and a host cannot be made to send one.
 *
 * Three §6 obligations live here and nowhere else in this SDK:
 *
 * - An `audit/attempt` is never batched. This binding sends one JSON-RPC message per frame and has no
 *   array form to put one in.
 * - The wait for a decision is bounded, and silence fails closed: an attempt that times out returns
 *   `unavailable`, which aborts the action rather than letting it run unrecorded (§7.2).
 * - Nothing is sent in an unnegotiated session (§6.2). `negotiate` is what opens the send path, so a
 *   transport that never negotiated, or negotiated and did not fit, refuses to send at all.
 */

import type { NegotiationResult } from '../capability';
import { negotiate } from '../capability';
import { type AttemptResponse, type AuditCapability, attemptResponseSchema } from '../models';
import { type AuditEndpoint, type AuditTransport, unavailable } from '../transport';
import { capabilityOf, declareInto, type WithExtensions } from './declaration';

/** The literal method names of §6. `params` IS the audit event object, never a wrapper. */
export const ATTEMPT_METHOD = 'audit/attempt';
export const OUTCOME_METHOD = 'audit/outcome';
export const INITIALIZE_METHOD = 'initialize';

/**
 * Audit request ids are strings under this prefix. An MCP session numbers its own requests with
 * integers, so the two id spaces cannot collide however long either side runs, and neither can claim
 * the other's response by accident.
 */
export const ID_PREFIX = 'amcp-';

/** §6 leaves the bound on the wait to the transport, requiring only that it fail closed. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** A JSON-RPC message as it crosses the transport, before either side has typed it. */
export interface JsonRpcFrame {
  jsonrpc: '2.0';
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
}

/**
 * The MCP transport surface this binding wraps and presents.
 *
 * Declared structurally rather than imported, so nothing here depends on the MCP package: an official
 * `Transport` satisfies it, and a seam satisfies what the session requires of a transport.
 */
export interface McpTransport {
  start(): Promise<void>;
  send(message: JsonRpcFrame, options?: unknown): Promise<void>;
  close(): Promise<void>;
  /** Set by the Streamable HTTP transports; it decides how the session cancels a request. */
  readonly hasPerRequestStream?: boolean | undefined;
  onmessage?: ((message: JsonRpcFrame, extra?: unknown) => void) | undefined;
  onclose?: (() => void) | undefined;
  onerror?: ((error: Error) => void) | undefined;
  sessionId?: string | undefined;
  setProtocolVersion?: ((version: string) => void) | undefined;
  /** Called during connect, for the header validation an HTTP transport performs. */
  setSupportedProtocolVersions?: ((versions: string[]) => void) | undefined;
}

/** The binding was driven into a state §6 does not define. */
export class McpBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpBindingError';
  }
}

/** Negotiation was asked for before the peer's `initialize` reached this seam (§6.1). */
export class HandshakeNotSeenError extends McpBindingError {
  constructor(message: string) {
    super(message);
    this.name = 'HandshakeNotSeenError';
  }
}

/** A send was attempted on a session that is not audit-negotiated (§6.2). */
export class UnnegotiatedSendError extends McpBindingError {
  constructor(message: string) {
    super(message);
    this.name = 'UnnegotiatedSendError';
  }
}

/** One in-flight `audit/attempt`, waiting for the host's decision. */
interface Pending {
  settle(response: AttemptResponse): void;
}

/** A frame that expects a response: it names a method and carries an id to answer under. */
type RequestFrame = JsonRpcFrame & { id: string | number; method: string };

function isRequest(frame: JsonRpcFrame): frame is RequestFrame {
  return frame.method !== undefined && frame.id !== undefined;
}

function isNotification(frame: JsonRpcFrame): boolean {
  return frame.method !== undefined && frame.id === undefined;
}

/**
 * Stream plumbing shared by both roles: pass MCP through, take `audit/*` out.
 *
 * The seam is what the session is given, so the session's own `onmessage` is held here and called for
 * everything this side does not own.
 */
abstract class FrameSeam implements McpTransport {
  protected readonly inner: McpTransport;
  #sessionMessage: ((message: JsonRpcFrame, extra?: unknown) => void) | undefined;
  #sessionClose: (() => void) | undefined;

  protected constructor(inner: McpTransport) {
    this.inner = inner;
    inner.onmessage = (message, extra) => {
      void this.receive(message, extra);
    };
    inner.onclose = () => {
      this.onConnectionLost();
      this.#sessionClose?.();
    };
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  async close(): Promise<void> {
    this.onConnectionLost();
    await this.inner.close();
  }

  /** Everything the session writes passes through, with this side's declaration added to the handshake. */
  async send(message: JsonRpcFrame, options?: unknown): Promise<void> {
    await this.inner.send(this.declareOn(message), options);
  }

  set onmessage(handler: ((message: JsonRpcFrame, extra?: unknown) => void) | undefined) {
    this.#sessionMessage = handler;
  }

  get onmessage(): ((message: JsonRpcFrame, extra?: unknown) => void) | undefined {
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
   * The session reads it to choose how it cancels a request: on a per-request-stream transport it
   * aborts that stream, and otherwise it sends `notifications/cancelled`. A seam that reported
   * `undefined` for a transport that sets it would change how ordinary MCP behaves on this
   * connection, which §6.2 does not permit this extension to do.
   */
  get hasPerRequestStream(): boolean | undefined {
    return this.inner.hasPerRequestStream;
  }

  /** Send one JSON-RPC message for this seam's own traffic. One message per frame, never an array (§6). */
  protected async sendFrame(frame: JsonRpcFrame): Promise<void> {
    await this.inner.send(frame);
  }

  private async receive(message: JsonRpcFrame, extra?: unknown): Promise<void> {
    if (await this.intercept(message)) {
      return;
    }
    this.#sessionMessage?.(message, extra);
  }

  /** Handle a frame this side owns; return true when the session must not see it. */
  protected abstract intercept(frame: JsonRpcFrame): Promise<boolean>;

  /** Add this side's declaration to the outgoing handshake, if this frame is it (§6.1). */
  protected declareOn(frame: JsonRpcFrame): JsonRpcFrame {
    return frame;
  }

  /** Release anything the role is holding. Nothing by default. */
  protected onConnectionLost(): void {}
}

/**
 * The tool side of the wire: an `AuditTransport` that speaks §6 over an MCP connection.
 *
 * A tool is an MCP server, so both halves of the handshake pass through this seam: the host's
 * declaration arrives in the `initialize` request, and the tool's goes out in the `initialize` result.
 * The seam reads the first and writes the second, so `negotiate` needs nothing passed in and what the
 * tool declared on the wire is what it negotiates with — there is no second copy to drift.
 */
export class McpAuditTransport extends FrameSeam implements AuditTransport {
  readonly #declares: AuditCapability;
  readonly #requestTimeoutMs: number;
  readonly #pending = new Map<string, Pending>();
  #nextId = 0;
  #handshakeId: string | number | undefined;
  #handshakeSeen = false;
  #hostCapability: AuditCapability | undefined;
  #negotiated = false;

  constructor(inner: McpTransport, declares: AuditCapability, options: { requestTimeoutMs?: number } = {}) {
    super(inner);
    this.#declares = declares;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  /** True once the peer's `initialize` has passed through this seam. */
  get handshakeSeen(): boolean {
    return this.#handshakeSeen;
  }

  /** What the host declared at `initialize`, or undefined if it declared nothing readable (§6.1). */
  get hostCapability(): AuditCapability | undefined {
    return this.#hostCapability;
  }

  /**
   * Compare the host's declaration against the tool's, and open the send path if they fit (§6.1).
   *
   * @throws {HandshakeNotSeenError} Called before the peer's `initialize` reached this seam. Until
   *   then an absent declaration is indistinguishable from one that has not arrived, and reading it
   *   as absent would degrade a session that was about to negotiate (§6.2).
   * @throws {McpBindingError} `offered` is not what this transport declared on the wire. Negotiating
   *   against a capability the host was never shown would make the outcome unverifiable by the peer
   *   that has to live with it (§6.1).
   */
  negotiate(offered: AuditCapability): NegotiationResult {
    if (!this.#handshakeSeen) {
      throw new HandshakeNotSeenError('the peer has not sent `initialize` yet; negotiate after the handshake (§6.1)');
    }
    if (JSON.stringify(offered) !== JSON.stringify(this.#declares)) {
      throw new McpBindingError('this transport declared a different capability at `initialize` (§6.1)');
    }
    const result = negotiate(this.#hostCapability, offered);
    this.#negotiated = result.negotiated;
    return result;
  }

  /** Send `audit/attempt` and block for the host's decision, failing closed on silence (§6, §7.2). */
  async sendAttempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    this.requireNegotiated();
    const id = `${ID_PREFIX}${++this.#nextId}`;
    let settle: (response: AttemptResponse) => void = () => {};
    const decided = new Promise<AttemptResponse>((resolve) => {
      settle = resolve;
    });
    this.#pending.set(id, { settle });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      // §6 bounds this wait at the transport, and a decision the tool never read is a failure to
      // record: the session aborts rather than acting unrecorded (§7.2).
      const bounded = new Promise<AttemptResponse>((resolve) => {
        timer = setTimeout(() => {
          console.error(`auditable-mcp: no decision for ${id} within ${this.#requestTimeoutMs}ms; failing closed`);
          resolve(unavailable());
        }, this.#requestTimeoutMs);
      });
      await this.sendFrame({ jsonrpc: '2.0', id, method: ATTEMPT_METHOD, params: event });
      return await Promise.race([decided, bounded]);
    } catch (error) {
      // A connection that has gone away answers nothing, which is what `unavailable` says. Letting
      // the transport's own error out instead would reach the tool as something other than an audit
      // decision, and a tool that branches on the decision (§7.2) would never see it.
      console.error(`auditable-mcp: ${ATTEMPT_METHOD} could not be sent; failing closed`, error);
      return unavailable();
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      this.#pending.delete(id);
    }
  }

  /** Send `audit/outcome` as a notification: reported, not awaited (§6). */
  async sendOutcome(event: Record<string, unknown>): Promise<void> {
    this.requireNegotiated();
    try {
      await this.sendFrame({ jsonrpc: '2.0', method: OUTCOME_METHOD, params: event });
    } catch (error) {
      // An outcome has no response channel and no retry in §6; the host detects the gap by the
      // attempt it sealed and never saw resolved, which is what §7.5 is for.
      console.error(`auditable-mcp: ${OUTCOME_METHOD} could not be sent`, error);
    }
  }

  protected async intercept(frame: JsonRpcFrame): Promise<boolean> {
    if (frame.method === INITIALIZE_METHOD && frame.id !== undefined) {
      this.#handshakeId = frame.id;
      this.#hostCapability = capabilityOf(frame.params?.capabilities);
      this.#handshakeSeen = true;
      return false;
    }
    if (frame.method !== undefined || typeof frame.id !== 'string') {
      return false;
    }
    const pending = this.#pending.get(frame.id);
    if (pending === undefined) {
      return false;
    }
    pending.settle(this.decision(frame));
    return true;
  }

  protected override declareOn(frame: JsonRpcFrame): JsonRpcFrame {
    if (frame.id !== this.#handshakeId || frame.result === undefined) {
      return frame;
    }
    const capabilities: WithExtensions = { ...((frame.result.capabilities as WithExtensions) ?? {}) };
    declareInto(capabilities, this.#declares);
    return { ...frame, result: { ...frame.result, capabilities } };
  }

  protected override onConnectionLost(): void {
    // A closed connection will not answer, and a tool left waiting would neither record nor abort.
    for (const pending of this.#pending.values()) {
      pending.settle(unavailable());
    }
    this.#pending.clear();
  }

  /** Read the host's decision, treating anything unreadable as a failure to record (§6, §7.2). */
  private decision(frame: JsonRpcFrame): AttemptResponse {
    if (frame.error !== undefined) {
      // §6 reserves JSON-RPC errors for protocol faults and requires the tool to read one for an
      // attempt as a failure to record, exactly as for `unavailable`.
      console.error(
        `auditable-mcp: ${ATTEMPT_METHOD} ${String(frame.id)} answered with a JSON-RPC error`,
        frame.error.message,
      );
      return unavailable();
    }
    const parsed = attemptResponseSchema.safeParse(frame.result);
    if (!parsed.success) {
      console.error(
        `auditable-mcp: ${ATTEMPT_METHOD} ${String(frame.id)} answered with an unreadable result`,
        parsed.error.message,
      );
      return unavailable();
    }
    return parsed.data;
  }

  private requireNegotiated(): void {
    if (!this.#negotiated) {
      throw new UnnegotiatedSendError(
        'this session is not audit-negotiated, so no audit message may be sent; ' +
          'choose the transport with `transportFor` after `negotiate` (§6.2)',
      );
    }
  }
}

/**
 * The host side of the wire: answers `audit/attempt` and seals `audit/outcome` (§6, §7).
 *
 * A host is an MCP client, and the tool's declaration comes back in the `initialize` result the
 * session already returns, so there is nothing to intercept for negotiation here: read it with
 * `capabilityOf(result.capabilities)`. The host's own declaration goes out on the handshake, and it is
 * `endpoint.capability` — the requirement the endpoint enforces at runtime (§7) and the one it
 * declares are the same object, so a host cannot advertise one thing and apply another.
 */
export class McpAuditReceiver extends FrameSeam {
  readonly #endpoint: AuditEndpoint;

  constructor(inner: McpTransport, endpoint: AuditEndpoint) {
    super(inner);
    this.#endpoint = endpoint;
  }

  protected async intercept(frame: JsonRpcFrame): Promise<boolean> {
    if (frame.method === ATTEMPT_METHOD && isRequest(frame)) {
      await this.answerAttempt(frame);
      return true;
    }
    if (frame.method === OUTCOME_METHOD && isNotification(frame)) {
      await this.sealOutcome(frame);
      return true;
    }
    if (frame.method === OUTCOME_METHOD && isRequest(frame)) {
      // §6 defines the outcome channel as a notification. One sent as a request is a malformed
      // envelope, which is what a JSON-RPC error is for, and it is not sealed either way.
      await this.sendFrame({
        jsonrpc: '2.0',
        id: frame.id,
        error: { code: -32600, message: `${OUTCOME_METHOD} is a notification (§6)` },
      });
      return true;
    }
    if (frame.method === ATTEMPT_METHOD && isNotification(frame)) {
      // An attempt sent without an id has no response channel, so it cannot be accepted and the tool
      // cannot be told. Sealing it anyway would record an operation the tool never learned it was
      // cleared for, which is the one thing §6 guarantees against.
      console.error(`auditable-mcp: ${ATTEMPT_METHOD} arrived as a notification; it cannot be answered`);
      return true;
    }
    return false;
  }

  protected override declareOn(frame: JsonRpcFrame): JsonRpcFrame {
    if (frame.method !== INITIALIZE_METHOD || frame.params === undefined) {
      return frame;
    }
    const capabilities: WithExtensions = { ...((frame.params.capabilities as WithExtensions) ?? {}) };
    declareInto(capabilities, this.#endpoint.capability);
    return { ...frame, params: { ...frame.params, capabilities } };
  }

  /** Hand the event to the endpoint and return its decision as a JSON-RPC result (§6, §7.1). */
  private async answerAttempt(frame: RequestFrame): Promise<void> {
    let response: AttemptResponse;
    try {
      response = await this.#endpoint.handleAttempt(frame.params ?? {});
    } catch (error) {
      // §6 requires every audit-layer decision to travel as a result, never as a JSON-RPC error, so
      // an endpoint that threw has to be turned into one. It recorded nothing, which is what
      // `unavailable` says, and the tool already fails closed on it (§7.2). Rethrowing would let a
      // host-side defect reach the tool as a protocol fault instead of an audit decision.
      console.error(`auditable-mcp: the audit endpoint threw while handling ${ATTEMPT_METHOD}`, error);
      response = unavailable();
    }
    await this.sendFrame({ jsonrpc: '2.0', id: frame.id, result: response });
  }

  /** Hand the outcome to the endpoint. A notification has no response channel (§6). */
  private async sealOutcome(frame: JsonRpcFrame): Promise<void> {
    try {
      await this.#endpoint.handleOutcome(frame.params ?? {});
    } catch (error) {
      // There is no channel to answer on, so the endpoint's own anomaly set is where this belongs
      // (§7.6). A throw instead of an anomaly is a host-side defect, and it changes nothing here.
      console.error(`auditable-mcp: the audit endpoint threw while handling ${OUTCOME_METHOD}`, error);
    }
  }
}
