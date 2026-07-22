import { describe, expect, it } from 'vitest';
import { BoundaryObserver, reconcile } from '../src/l2';
import type { SealedRecord } from '../src/ledger';

function egressRecord(callId: string, ref: string): SealedRecord {
  return {
    event: { call_id: callId, egress: true, target_resource: { kind: 'api', ref } },
    seq: 0,
    host_ts: '2026-07-15T00:00:01.000Z',
    previous_hash: '0'.repeat(64),
    record_hash: '0'.repeat(64),
  };
}

describe('BoundaryObserver', () => {
  it('records and returns observations for a call', () => {
    const observer = new BoundaryObserver();
    observer.observeEgress('call-1', 'api.example.com');
    observer.observeEgress('call-2', 'other.example.com');
    expect(observer.forCall('call-1')).toEqual([{ callId: 'call-1', destination: 'api.example.com' }]);
  });
});

describe('reconcile detects suppression by omission (§7.5)', () => {
  it('flags an observed egress with no self-report', () => {
    const observer = new BoundaryObserver();
    observer.observeEgress('call-1', 'evil.example.com');
    const anomalies = reconcile([], observer.forCall('call-1'), 'call-1');
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]?.kind).toBe('unreported-egress');
    expect(anomalies[0]?.destination).toBe('evil.example.com');
  });

  it('does not flag an egress that was self-reported', () => {
    const observer = new BoundaryObserver();
    observer.observeEgress('call-1', 'api.example.com');
    const anomalies = reconcile([egressRecord('call-1', 'api.example.com')], observer.forCall('call-1'), 'call-1');
    expect(anomalies).toHaveLength(0);
  });

  it('does not flag a self-report the boundary did not observe (boundaries are not omniscient)', () => {
    const anomalies = reconcile([egressRecord('call-1', 'api.example.com')], [], 'call-1');
    expect(anomalies).toHaveLength(0);
  });
});
