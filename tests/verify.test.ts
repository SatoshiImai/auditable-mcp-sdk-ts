import { describe, expect, it } from 'vitest';
import type { SealedRecord } from '../src/ledger';
import { Ledger } from '../src/ledger';
import { firstSealedValidationError, firstValidationError } from '../src/models';
import {
  DEFAULT_ADAPTER,
  DIGEST_MISMATCH,
  ORPHANED_OUTCOME,
  PRINCIPAL_MISMATCH,
  RECORD_HASH_MISMATCH,
  type RecordAdapter,
  SCHEMA_INVALID,
  SEQ_GAP,
  verifyChain,
  verifyLedger,
} from '../src/verify';
import { chainSignedVector, chainVector } from './vectors';

function boundaryEvent(id: string, outcome = 'attempted'): Record<string, unknown> {
  return { id, actor: 'odin', tenant: 'tenant-a', category: 'boundary', outcome };
}

function amcpEvent(
  id: string,
  outcome = 'attempted',
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id,
    spec_version: 'auditable-mcp/0.2',
    ts: '2026-07-15T00:00:01.000Z',
    call_id: 'call_abc',
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome,
    ...overrides,
  };
}

describe('verifyLedger is read-lenient on spec_version', () => {
  it('verifies a chain sealed under an earlier published spec_version (immutable evidence)', () => {
    const ledger = new Ledger('tenant-a');
    const legacy = { spec_version: 'auditable-mcp/0.1.1' };
    ledger.append(amcpEvent('00000000-0000-4000-8000-000000000001', 'attempted', legacy), '2026-07-15T00:00:01.000Z');
    ledger.append(amcpEvent('00000000-0000-4000-8000-000000000001', 'success', legacy), '2026-07-15T00:00:02.000Z');
    const report = verifyLedger(ledger.records());
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
  });

  it('ingest stays strict while verification is lenient (read/write split)', () => {
    const legacy = amcpEvent('00000000-0000-4000-8000-000000000001', 'attempted', {
      spec_version: 'auditable-mcp/0.1.1',
    });
    expect(firstValidationError(legacy)).not.toBeNull();
    expect(firstSealedValidationError(legacy)).toBeNull();
  });
});

function enveloped(amcp: Record<string, unknown>): Record<string, unknown> {
  return { schema: 'sep3004', sealed_at: '2026-07-15T00:00:00Z', amcp };
}

describe('verifyLedger reaches into an envelope via an adapter', () => {
  it('correlates and schema-checks a-MCP events sealed inside SEP-3004 envelopes', () => {
    const ledger = new Ledger('tenant-a');
    ledger.append(
      enveloped(amcpEvent('00000000-0000-4000-8000-000000000001', 'attempted')),
      '2026-07-15T00:00:01.000Z',
    );
    ledger.append(enveloped(amcpEvent('00000000-0000-4000-8000-000000000001', 'success')), '2026-07-15T00:00:02.000Z');
    const adapter: RecordAdapter = {
      idOf: (event) => (event.amcp as Record<string, unknown>).id,
      isAttempt: (event) => (event.amcp as Record<string, unknown>).outcome === 'attempted',
      eventOf: (event) => event.amcp,
    };
    const report = verifyLedger(ledger.records(), undefined, adapter);
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
  });

  it('the default adapter cannot read an envelope (schema-invalid)', () => {
    const ledger = new Ledger('tenant-a');
    ledger.append(
      enveloped(amcpEvent('00000000-0000-4000-8000-000000000001', 'attempted')),
      '2026-07-15T00:00:01.000Z',
    );
    const kinds = verifyLedger(ledger.records()).issues.map((i) => i.kind);
    expect(kinds).toContain(SCHEMA_INVALID);
  });
});

describe('verifyChain exempts a record that names no call from correlation', () => {
  it('does not flag records whose idOf is undefined (a prompt, reasoning) as orphaned outcomes', () => {
    const ledger = new Ledger('tenant-a');
    ledger.append({ kind: 'prompt', text: 'prompt 1' }, '2026-07-15T00:00:01.000Z');
    ledger.append({ kind: 'reasoning', text: 'reasoning 2' }, '2026-07-15T00:00:02.000Z');
    ledger.append({ kind: 'reasoning', text: 'reasoning 3' }, '2026-07-15T00:00:03.000Z');
    const adapter: RecordAdapter = { ...DEFAULT_ADAPTER, idOf: () => undefined, isAttempt: () => false };
    const report = verifyChain(ledger.records(), undefined, adapter);
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
  });

  it('does not seed a wildcard: a real orphan whose id is present is still reported', () => {
    const ledger = new Ledger('tenant-a');
    ledger.append({ kind: 'prompt' }, '2026-07-15T00:00:01.000Z');
    ledger.append({ kind: 'tool', call: 'call-1' }, '2026-07-15T00:00:02.000Z');
    const adapter: RecordAdapter = { ...DEFAULT_ADAPTER, idOf: (event) => event.call, isAttempt: () => false };
    const report = verifyChain(ledger.records(), undefined, adapter);
    expect(report.issues.map((i) => i.kind)).toEqual([ORPHANED_OUTCOME]);
  });
});

function boundPair(principalAttempt: string, principalOutcome: string): Ledger {
  const eid = '00000000-0000-4000-8000-000000000001';
  const ledger = new Ledger('tenant-a');
  ledger.append(amcpEvent(eid, 'attempted', { principal_id: principalAttempt }), '2026-07-15T00:00:01.000Z');
  ledger.append(amcpEvent(eid, 'success', { principal_id: principalOutcome }), '2026-07-15T00:00:02.000Z');
  return ledger;
}

describe('verifyChain matches the governed identity against expectedPrincipal', () => {
  const withPrincipal: RecordAdapter = { ...DEFAULT_ADAPTER, principalOf: (event) => event.principal_id };

  it('is clean when every record names the expected principal', () => {
    const report = verifyChain(boundPair('tenant-a', 'tenant-a').records(), undefined, withPrincipal, 'tenant-a');
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
  });

  it('flags a single foreign record principal-mismatch on its seq (per-record)', () => {
    const report = verifyChain(boundPair('tenant-a', 'tenant-b').records(), undefined, withPrincipal, 'tenant-a');
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.seq, i.kind])).toEqual([[1, PRINCIPAL_MISMATCH]]);
  });

  it('flags a transplanted chain principal-mismatch throughout (hash and chain still pass)', () => {
    const report = verifyChain(boundPair('tenant-a', 'tenant-a').records(), undefined, withPrincipal, 'tenant-b');
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => i.kind)).toEqual([PRINCIPAL_MISMATCH, PRINCIPAL_MISMATCH]);
  });

  it('fails closed when a record binds no identity but a principal is expected', () => {
    const report = verifyChain(boundPair('tenant-a', 'tenant-a').records(), undefined, DEFAULT_ADAPTER, 'tenant-a');
    expect(report.ok).toBe(false);
    expect(report.issues.every((i) => i.kind === PRINCIPAL_MISMATCH)).toBe(true);
  });

  it('skips the check when expectedPrincipal is omitted (backward compatible)', () => {
    expect(verifyChain(boundPair('tenant-a', 'tenant-a').records(), undefined, withPrincipal).ok).toBe(true);
  });

  it('matches the principal through an envelope in verifyLedger; a transplant fails', () => {
    const eid = '00000000-0000-4000-8000-000000000001';
    const ledger = new Ledger('tenant-a');
    ledger.append(
      { schema: 'sep3004', principal_id: 'tenant-a', amcp: amcpEvent(eid, 'attempted') },
      '2026-07-15T00:00:01.000Z',
    );
    ledger.append(
      { schema: 'sep3004', principal_id: 'tenant-a', amcp: amcpEvent(eid, 'success') },
      '2026-07-15T00:00:02.000Z',
    );
    const adapter: RecordAdapter = {
      idOf: (event) => (event.amcp as Record<string, unknown>).id,
      isAttempt: (event) => (event.amcp as Record<string, unknown>).outcome === 'attempted',
      eventOf: (event) => event.amcp,
      principalOf: (event) => event.principal_id,
    };
    expect(verifyLedger(ledger.records(), undefined, adapter, 'tenant-a').ok).toBe(true);
    const transplant = verifyLedger(ledger.records(), undefined, adapter, 'tenant-b');
    expect(transplant.issues.map((i) => i.kind)).toEqual([PRINCIPAL_MISMATCH, PRINCIPAL_MISMATCH]);
  });

  it('treats principal equality as strict (case- and whitespace-sensitive)', () => {
    const report = verifyChain(boundPair('Tenant-A', 'tenant-a ').records(), undefined, withPrincipal, 'tenant-a');
    expect(report.issues.map((i) => [i.seq, i.kind])).toEqual([
      [0, PRINCIPAL_MISMATCH],
      [1, PRINCIPAL_MISMATCH],
    ]);
  });

  it('reports principal-mismatch alongside record-hash-mismatch (neither masks the other)', () => {
    const src = boundPair('tenant-a', 'tenant-a').records();
    const records = src.map((r) => ({ ...r, event: { ...r.event } }));
    (records[1] as { event: Record<string, unknown> }).event.outcome = 'failed';
    const report = verifyChain(records, undefined, withPrincipal, 'tenant-b');
    const kinds = new Set(report.issues.map((i) => i.kind));
    expect(kinds.has(RECORD_HASH_MISMATCH)).toBe(true);
    expect(kinds.has(PRINCIPAL_MISMATCH)).toBe(true);
  });
});

function sealedBoundaryPair(): Ledger {
  const ledger = new Ledger('tenant-a');
  ledger.append(boundaryEvent('call-1', 'attempted'), '2026-07-15T00:00:01.000Z');
  ledger.append(boundaryEvent('call-1', 'denied'), '2026-07-15T00:00:02.000Z');
  return ledger;
}

function cloneRecords(): SealedRecord[] {
  return chainVector.records.map((r) => ({ ...r, event: { ...r.event } }));
}

describe('verifyLedger accepts a sound golden chain', () => {
  it('reports ok=true with the digest equal to the chain digest', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[]);
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
    expect(report.computedDigest).toBe(chainVector.digest);
    expect(report.count).toBe(chainVector.records.length);
  });

  it('reproduces the signed golden chain (record_hash includes the signature, §8.2)', () => {
    const report = verifyLedger(chainSignedVector.records as SealedRecord[]);
    expect(report.ok).toBe(true);
    expect(report.computedDigest).toBe(chainSignedVector.digest);
  });

  it('stays ok when the anchored digest matches', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[], chainVector.digest);
    expect(report.ok).toBe(true);
  });
});

describe('verifyLedger detects tampering with Tier-1 anomaly kinds (§7.6)', () => {
  it('flags record-hash-mismatch when an event is mutated', () => {
    const records = cloneRecords();
    (records[0] as { event: Record<string, unknown> }).event.action_type = 'tampered';
    const report = verifyLedger(records);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
  });

  it('flags record-hash-mismatch when a previous_hash link is broken', () => {
    const records = cloneRecords();
    (records[1] as { previous_hash: string }).previous_hash = '0'.repeat(64);
    const report = verifyLedger(records);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
  });

  it('flags seq-gap when a sequence jumps', () => {
    const records = cloneRecords();
    (records[1] as { seq: number }).seq = 5;
    const report = verifyLedger(records);
    expect(report.issues.some((i) => i.kind === SEQ_GAP)).toBe(true);
  });

  it('flags digest-mismatch on an anchored-digest mismatch (truncation / rewrite)', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[], 'f'.repeat(64));
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === DIGEST_MISMATCH)).toBe(true);
  });
});

describe('verifyChain audits a non-A-MCP envelope schema-free', () => {
  it('accepts a boundary chain that verifyLedger rejects as schema-invalid', () => {
    const ledger = sealedBoundaryPair();
    const records = ledger.records();
    const chain = verifyChain(records, ledger.digest());
    expect(chain.ok).toBe(true);
    expect(chain.computedDigest).toBe(ledger.digest());
    expect(verifyLedger(records, ledger.digest()).issues.some((i) => i.kind === SCHEMA_INVALID)).toBe(true);
  });

  it('still detects a mutated body, and never emits schema-invalid', () => {
    const records = sealedBoundaryPair().records();
    records[1] = { ...(records[1] as SealedRecord), event: boundaryEvent('call-1', 'expired') };
    const report = verifyChain(records);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
    expect(report.issues.some((i) => i.kind === SCHEMA_INVALID)).toBe(false);
  });

  it('still detects a seq gap', () => {
    const ledger = new Ledger('tenant-a');
    for (let n = 1; n <= 3; n += 1) {
      ledger.append(boundaryEvent(`call-${n}`), `2026-07-15T00:00:0${n}.000Z`);
    }
    const records = ledger.records();
    records.splice(1, 1);
    expect(verifyChain(records).issues.some((i) => i.kind === SEQ_GAP)).toBe(true);
  });
});
