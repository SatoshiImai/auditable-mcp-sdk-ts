/**
 * Ambient session binding for Node (the `AsyncLocalStorage` adapter).
 *
 * This is the Node counterpart to Python's `bound_session` / `ContextVar`: it carries an `AmcpSession`
 * implicitly across an async call tree so a deep function can audit without threading the session
 * through every signature. It lives in the `./node` entry because `AsyncLocalStorage` is a Node API;
 * universal callers pass the session explicitly to `withAudit` instead.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import type { AmcpSession, AuditedAction } from '../session';
import { type AuditSpec, withAudit } from '../with-audit';

const storage = new AsyncLocalStorage<AmcpSession>();

/** Run `fn` with `session` bound as the ambient session for its whole async subtree. */
export function runWithSession<T>(session: AmcpSession, fn: () => T): T {
  return storage.run(session, fn);
}

/** Return the ambient session, or throw if none is bound. */
export function currentSession(): AmcpSession {
  const session = storage.getStore();
  if (session === undefined) {
    throw new Error('no AmcpSession is bound; run inside runWithSession(session, ...)');
  }
  return session;
}

/** `withAudit` against the ambient session — the decorator-free equivalent of `@auditable_tool`. */
export function audited<T>(spec: AuditSpec, handler: (action: AuditedAction) => Promise<T> | T): Promise<T> {
  return withAudit(currentSession(), spec, handler);
}
