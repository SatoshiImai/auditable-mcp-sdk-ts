/**
 * Timestamp source for the spec's `ts` (tool-observed) and `host_ts` (authoritative) times.
 *
 * `nowIso` is the single formatter for both (ISO-8601 to milliseconds, `Z` suffix). `Clock` is the
 * injection seam used by the host and session so time can be made deterministic in tests.
 */

/** Return the current UTC time as `YYYY-MM-DDThh:mm:ss.sssZ`. */
export function nowIso(): string {
  // Date#toISOString always emits millisecond precision and a `Z` suffix, matching the spec pattern.
  return new Date().toISOString();
}

/** A source of ISO-8601 timestamps, injected so time can be made deterministic. */
export interface Clock {
  now(): string;
}

/** A `Clock` backed by the system wall clock. */
export class SystemClock implements Clock {
  now(): string {
    return nowIso();
  }
}
