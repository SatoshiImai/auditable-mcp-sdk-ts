/**
 * Conformance: every event in `error-cases.json` must be rejected (attempt channel) or dropped and
 * flagged (outcome channel) with the pinned Tier-1 reason / anomaly kind (§7.6).
 */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../../src/host';
import { MonotonicClock } from '../helpers';
import { errorCases } from '../vectors';

describe('error-cases.json: a host rejects or flags each with its Tier-1 code', () => {
  for (const testCase of errorCases) {
    it(`${testCase.name} (${testCase.channel})`, async () => {
      const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });

      if (testCase.channel === 'attempt') {
        const response = await host.handleAttempt(testCase.event);
        expect(response.status).toBe(testCase.expect.status);
        if (response.status === 'reject') {
          expect(response.reason).toBe(testCase.expect.reason);
        }
      } else {
        await host.handleOutcome(testCase.event);
        expect(host.records()).toHaveLength(0);
        if (testCase.expect.anomaly_kind !== undefined) {
          expect(host.anomalies().some((a) => a.kind === testCase.expect.anomaly_kind)).toBe(true);
        }
      }
    });
  }
});
