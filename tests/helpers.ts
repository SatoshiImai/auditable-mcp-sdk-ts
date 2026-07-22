/**
 * Shared test doubles: a deterministic clock/deps, stub L2 signer/verifiers, and an attempt builder.
 * These mirror the fixtures the Python SDK's host/session tests use, so both suites drive the same
 * scenarios.
 */

import type { Clock } from '../src/clock';
import type { SignatureVerifier } from '../src/host';
import type { SealedRecord } from '../src/ledger';
import type { Deps, EventSigner } from '../src/session';
import { type LedgerRepository, RepositoryError } from '../src/storage/repository';

/** A monotonic host clock producing valid ISO-8601 timestamps. */
export class MonotonicClock implements Clock {
  #n = 0;
  now(): string {
    this.#n += 1;
    return `2026-07-15T00:00:${String(this.#n).padStart(2, '0')}.000Z`;
  }
}

/** Deterministic id/time source for the session tests. */
export class FixedDeps implements Deps {
  #n = 0;
  newId(): string {
    this.#n += 1;
    return `00000000-0000-4000-8000-${this.#n.toString(16).padStart(12, '0')}`;
  }
  now(): string {
    return '2026-07-15T00:00:01.000Z';
  }
}

/** Stamps monotonic L2 fields so an L2 session can drive the host. */
export class StubSigner implements EventSigner {
  #seq = 0;
  async sign(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.#seq += 1;
    return { ...event, key_id: 'k1', sequence: this.#seq, signature: 'stub' };
  }
}

/** A verifier that accepts every signature. */
export class OkVerifier implements SignatureVerifier {
  async verify(): Promise<string | null> {
    return null;
  }
}

/** A verifier that rejects every signature as forged. */
export class BadVerifier implements SignatureVerifier {
  async verify(): Promise<string | null> {
    return 'signature-invalid';
  }
}

/** A repository whose `append` always fails, to exercise the fail-closed path. */
export class FailingRepository implements LedgerRepository {
  async append(): Promise<void> {
    throw new RepositoryError('storage down');
  }
  async loadTail(): Promise<SealedRecord | null> {
    return null;
  }
  async readAll(): Promise<SealedRecord[]> {
    return [];
  }
}

/** Build a wire attempt event. */
export function makeAttempt(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    spec_version: 'auditable-mcp/0.1',
    ts: '2026-07-15T00:00:01.000Z',
    call_id: 'call_abc',
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    ...overrides,
  };
}

/** Stamp an event with L2 fields at a given sequence. */
export function signed(event: Record<string, unknown>, sequence: number): Record<string, unknown> {
  return { ...event, key_id: 'k1', sequence, signature: 'stub' };
}

/** A stable set of valid event ids. */
export function eventIdAt(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
}
