/**
 * Round affinity under the Streamable HTTP transport (§6.4): the names both sides put on the wire, and
 * the round token's shape.
 *
 * Every request of an audited call carries `Auditable-Mcp-Session`, whose value mirrors the body's
 * `session_id`, so that an intermediary can route a call's requests to the instance that holds it without
 * parsing the body. The body is the source of truth; the header authenticates nothing.
 *
 * A round token names the instance that issued it: `amcp.<instance>.<random>`. The token is the tool's
 * alone and the specification does not fix its form; both SDKs mint this one so that either can forward a
 * retry to the instance that holds its round. The random part is what finds the held state, and a client
 * cannot guess it; the instance part only selects where a retry is forwarded, among the instances the
 * deployment itself registered.
 */

import { bytesToBase64url } from '../crypto/base64';

/** The request header that mirrors the body's `session_id` (§6.4). Compared case-insensitively. */
export const AFFINITY_HEADER = 'Auditable-Mcp-Session';

/**
 * Set by a forwarder on the request it forwards. An instance never forwards a request that carries it, so a
 * forward cannot loop; a client that sets it only gives up being forwarded.
 */
export const FORWARDED_HEADER = 'Auditable-Mcp-Forwarded';
export const FORWARDED_VALUE = '1';

/** The JSON-RPC error a header that disagrees with its body is answered with (`HeaderMismatch`). */
export const HEADER_MISMATCH = -32020;
export const HEADER_MISMATCH_STATUS = 400;

/**
 * Every `requestState` the seam issues starts with this prefix. A `tools/call` carrying one that is not a
 * round currently open is a replay or a forgery, and is refused rather than served as a new call (§6.4 at
 * most once) - so no record of consumed rounds has to be kept. The prefix is reserved: a tool's own
 * `requestState` (its own `inputRequests` rounds) must not begin with it, or its retry would be taken for
 * one of the seam's rounds and refused.
 */
export const ROUND_TOKEN_PREFIX = 'amcp.';

/** What an instance name may be: it travels in the token, so it is kept to URL-safe characters. */
export const INSTANCE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

const INSTANCE_BYTES = 16;
const ROUND_TOKEN_BYTES = 32;
/** The unpadded base64url length of `ROUND_TOKEN_BYTES` random bytes. */
const ROUND_TOKEN_RANDOM_LENGTH = 43;
const ROUND_TOKEN_RANDOM_PATTERN = /^[A-Za-z0-9_-]+$/;

function randomBase64url(bytes: number): string {
  return bytesToBase64url(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}

/** A fresh instance name: 16 random bytes, so a restarted process never claims a token it did not issue. */
export function newInstanceId(): string {
  return randomBase64url(INSTANCE_BYTES);
}

/** The instance name every seam in this process uses unless it is given one. */
export const PROCESS_INSTANCE = newInstanceId();

/** True when `instance` may name an instance in a round token. */
export function isInstanceId(instance: string): boolean {
  return INSTANCE_PATTERN.test(instance);
}

/** A round token owned by `instance`, whose random part is what finds the held state. */
export function mintRoundToken(instance: string): string {
  return `${ROUND_TOKEN_PREFIX}${instance}.${randomBase64url(ROUND_TOKEN_BYTES)}`;
}

/**
 * The instance a round token names, or undefined when the value is not a token of this form. Nothing is
 * resolved from the result here: where it may lead is the deployment's resolver's decision.
 */
export function instanceOfToken(token: string): string | undefined {
  if (!token.startsWith(ROUND_TOKEN_PREFIX)) {
    return undefined;
  }
  const rest = token.slice(ROUND_TOKEN_PREFIX.length);
  const dot = rest.indexOf('.');
  if (dot < 0) {
    return undefined;
  }
  const instance = rest.slice(0, dot);
  const random = rest.slice(dot + 1);
  if (
    !isInstanceId(instance) ||
    random.length !== ROUND_TOKEN_RANDOM_LENGTH ||
    !ROUND_TOKEN_RANDOM_PATTERN.test(random)
  ) {
    return undefined;
  }
  return instance;
}

/**
 * Headers as a transport's per-request carrier holds them, with the affinity header set to `sessionId` and
 * any other spelling of it removed.
 */
export function withAffinityHeader(
  headers: Readonly<Record<string, string>> | undefined,
  sessionId: string,
): Record<string, string> {
  const result: Record<string, string> = {};
  const lower = AFFINITY_HEADER.toLowerCase();
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (name.toLowerCase() !== lower) {
      result[name] = value;
    }
  }
  result[AFFINITY_HEADER] = sessionId;
  return result;
}
