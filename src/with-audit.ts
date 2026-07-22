/**
 * `withAudit` — the recommended tool-side DX over the `await using` core.
 *
 * The `await using` primitive (session.ts) cannot observe whether its block threw, so it fails closed
 * to `failed` unless `succeeded()` is called. `withAudit` restores the full Python-`async with`
 * semantics by wrapping the handler in try/catch: a returned value maps to `success`, a thrown error
 * to `failed`, automatically. Prefer this for ordinary use; drop to `await using` only when you want
 * to drive the outcome explicitly.
 *
 * If the host refuses the attempt, `session.action` throws `AmcpAbortedError` before the handler runs
 * (the `aborted` outcome is already emitted), so the handler never sees a non-accepted action.
 */

import type { TargetResource } from './models';
import type { ActionOptions, AmcpSession, AuditedAction } from './session';

/** The declarative descriptor for one audited action. */
export interface AuditSpec extends ActionOptions {
  actionType: string;
  targetResource: TargetResource | Record<string, unknown>;
}

/**
 * Run `handler` inside an audited action, mapping its result to the terminal outcome automatically.
 *
 * @param session The bound session.
 * @param spec The action descriptor (action type, target, effect, and optional confidentiality).
 * @param handler The domain action; its return is recorded as `success`, a throw as `failed`.
 * @returns The handler's result.
 * @throws {AmcpAbortedError} If the host refuses the attempt (the handler does not run).
 */
export async function withAudit<T>(
  session: AmcpSession,
  spec: AuditSpec,
  handler: (action: AuditedAction) => Promise<T> | T,
): Promise<T> {
  const action = await session.action(spec.actionType, spec.targetResource, spec);
  try {
    const result = await handler(action);
    action.succeeded();
    return result;
  } catch (error) {
    action.failed();
    throw error;
  } finally {
    await action[Symbol.asyncDispose]();
  }
}
