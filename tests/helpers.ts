/**
 * Shared test doubles: a deterministic clock/deps, stub L2 signer/verifiers, and an attempt builder.
 * These mirror the fixtures the Python SDK's host/session tests use, so both suites drive the same
 * scenarios.
 */

import type { Clock } from '../src/clock';
import type { SignatureVerifier } from '../src/host';
import type { SealedRecord } from '../src/ledger';
import {
  type AttemptResponse,
  type AuditCapability,
  Countersign,
  Level,
  type RejectReason,
  SPEC_VERSION,
} from '../src/models';
import type { Deps, EventSigner } from '../src/session';
import { type LedgerRepository, RepositoryError } from '../src/storage/repository';
import type { AuditEndpoint } from '../src/transport';

/** The audit session the tests' events belong to (§6.3). */
export const SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0';

/** A host's countersignatures name its partition unless told otherwise (§7.1). */
export const LOG_ID = 'tenant-a';

/** An L2 host/tool capability at the current spec version. */
export const L2_CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L2,
  attempt: 'request',
  countersign: Countersign.NONE,
};

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
  readonly keyId = 'k1';
  async sign(event: Record<string, unknown>, signerSeq: number): Promise<Record<string, unknown>> {
    return { ...event, key_id: this.keyId, signer_seq: signerSeq, signature: 'stub' };
  }
}

/** A verifier that accepts every signature. */
export class OkVerifier implements SignatureVerifier {
  async verify(): Promise<RejectReason | null> {
    return null;
  }
}

/** A verifier that rejects every signature as forged. */
export class BadVerifier implements SignatureVerifier {
  async verify(): Promise<RejectReason | null> {
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

/** A repository whose `append` fails while `fail` is set, mirroring the Python suite's fixture. */
export class FlakyRepository implements LedgerRepository {
  fail = false;
  readonly records = new Map<string, SealedRecord[]>();

  async append(partition: string, record: SealedRecord): Promise<void> {
    if (this.fail) {
      throw new RepositoryError('storage down');
    }
    const existing = this.records.get(partition) ?? [];
    existing.push(record);
    this.records.set(partition, existing);
  }
  async loadTail(partition: string): Promise<SealedRecord | null> {
    const existing = this.records.get(partition) ?? [];
    return existing[existing.length - 1] ?? null;
  }
  async readAll(partition: string): Promise<SealedRecord[]> {
    return [...(this.records.get(partition) ?? [])];
  }
}

/** Build a wire attempt event. */
export function makeAttempt(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    spec_version: SPEC_VERSION,
    ts: '2026-07-15T00:00:01.000Z',
    session_id: SESSION,
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    ...overrides,
  };
}

/** Stamp an event with L2 fields at a given signer_seq. */
export function signed(event: Record<string, unknown>, signerSeq: number): Record<string, unknown> {
  return { ...event, key_id: 'k1', signer_seq: signerSeq, signature: 'stub' };
}

/** A stable set of valid event ids. */
export function eventIdAt(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
}

/**
 * A stand-in endpoint whose session bookkeeping a test does not care about: it answers the one session
 * the tests use, and forwards attempts and outcomes to the functions it is given.
 */
export abstract class StubEndpoint implements AuditEndpoint {
  abstract readonly capability: AuditCapability;
  openSession(sessionId?: string): string {
    return sessionId ?? SESSION;
  }
  async closeSession(): Promise<void> {}
  abstract handleAttempt(event: Record<string, unknown>, sessionId?: string): Promise<AttemptResponse>;
  abstract handleOutcome(event: Record<string, unknown>, sessionId?: string): Promise<void>;
}
