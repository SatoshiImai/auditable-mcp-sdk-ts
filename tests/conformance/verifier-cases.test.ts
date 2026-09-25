/**
 * Conformance: the verifier's out-of-band inputs and record-level findings (`verifier-cases.json`,
 * §10.10, §11.4), with the vector's host keys as the countersignature registry.
 */

import { describe, expect, it } from 'vitest';
import { base64urlToBytes } from '../../src/crypto/base64';
import { CountersignatureRegistryVerifier, KeyRegistry, KeyRole, SignatureAlgorithm } from '../../src/l2';
import type { SealedRecord } from '../../src/ledger';
import { type VerifyOptions, verifyLedger } from '../../src/verify';
import { type VerifierCase, verifierCasesVector } from '../vectors';

function optionsOf(testCase: VerifierCase): VerifyOptions {
  const { countersignature_required: required, expected_identity: identity } = testCase.options;
  return {
    ...(required === undefined ? {} : { countersignatureRequired: required }),
    ...(identity === undefined
      ? {}
      : { expectedIdentity: { logId: identity.log_id, hostKeyIds: new Set(identity.host_key_ids) } }),
  };
}

describe('verifier-cases.json: the anomaly kinds each ledger yields (§11.4)', () => {
  const registry = new KeyRegistry(KeyRole.HOST);
  for (const [keyId, { jwk }] of Object.entries(verifierCasesVector.keys)) {
    registry.register(keyId, base64urlToBytes(jwk.x as string) as Uint8Array, SignatureAlgorithm.ED25519);
  }
  const check = new CountersignatureRegistryVerifier(registry).check;

  for (const testCase of verifierCasesVector.cases) {
    it(testCase.name, () => {
      const report = verifyLedger(
        testCase.records as unknown as SealedRecord[],
        undefined,
        undefined,
        undefined,
        check,
        undefined,
        optionsOf(testCase),
      );
      expect(report.issues.map((issue) => issue.kind).sort()).toEqual(testCase.expect_kinds);
    });
  }
});
