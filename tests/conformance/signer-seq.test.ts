/**
 * Conformance: the host's replay window (`signer-seq-replay.json`, §7.4) and the verifier's accounting of
 * `signer_seq` (`signer-seq-accounting.json`, §11.4), step by step as the vectors pin them.
 */

import { describe, expect, it } from 'vitest';
import { base64urlToBytes } from '../../src/crypto/base64';
import { AuditHost } from '../../src/host';
import { KeyRegistry, KeyRegistryVerifier, SignatureAlgorithm } from '../../src/l2';
import { unaccountedSignerSeq } from '../../src/verify';
import { L2_CAPABILITY, MonotonicClock } from '../helpers';
import { signerSeqAccountingCases, signerSeqReplayVector } from '../vectors';

describe('signer-seq-replay.json: the decided set, step by step (§7.4)', () => {
  it('every step answers, seals, and flags as pinned', async () => {
    const registry = new KeyRegistry();
    for (const [keyId, { jwk }] of Object.entries(signerSeqReplayVector.keys)) {
      registry.register(keyId, base64urlToBytes(jwk.x) as Uint8Array, SignatureAlgorithm.ED25519);
    }
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new KeyRegistryVerifier(registry),
      clock: new MonotonicClock(),
    });
    const sessions = new Set(signerSeqReplayVector.steps.map((step) => String(step.event.session_id)));
    for (const sessionId of sessions) {
      host.openSession(sessionId);
    }
    for (const step of signerSeqReplayVector.steps) {
      host.persistenceAvailable = step.host_available;
      const anomaliesBefore = host.anomalies().length;
      const recordsBefore = host.records().length;
      if (step.channel === 'attempt') {
        const response = await host.handleAttempt(step.event, String(step.event.session_id));
        expect(response.status, step.name).toBe(step.expect.status);
        if (response.status === 'accept') {
          expect(response.seq, step.name).toBe(step.expect.seq);
        } else {
          expect(response.reason, step.name).toBe(step.expect.reason);
        }
      } else {
        await host.handleOutcome(step.event, String(step.event.session_id));
        expect(host.records().length > recordsBefore, step.name).toBe(step.expect.sealed);
      }
      expect(
        host
          .anomalies()
          .slice(anomaliesBefore)
          .map((anomaly) => anomaly.kind),
        step.name,
      ).toEqual(step.expect.anomalies);
    }
  });
});

describe('signer-seq-accounting.json: the unaccounted values (§11.4)', () => {
  for (const testCase of signerSeqAccountingCases) {
    it(testCase.name, () => {
      expect(unaccountedSignerSeq(testCase.records)).toEqual(testCase.unaccounted);
    });
  }
});
