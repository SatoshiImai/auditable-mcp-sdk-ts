/**
 * The public surface of the countersign axis (§5.2, §6.2).
 *
 * Every analogous name for the level axis is exported, so these must be too. `Countersign` is the sharpest
 * case: the capability REQUIRES the field, so a user who cannot import the enum has to write the
 * string. The rest mirror names the package already exports for Level 2 — `Ed25519Signer`,
 * `KeyRegistryVerifier`, `verifyEd25519Signature`, `computeRecordHash`.
 */

import { describe, expect, it } from 'vitest';
import * as sdk from '../src/index';

const COUNTERSIGN_AXIS = [
  'EXTENSION_ID',
  'Ed25519Countersigner',
  'Posture',
  'UnnegotiatedCallError',
  'Countersign',
  'CountersignatureRegistryVerifier',
  'transportFor',
  'verifyDetachedSignature',
  'countersignaturePayload',
  'countersignSatisfies',
] as const;

describe('public surface', () => {
  it('exports the whole countersign axis', () => {
    const missing = COUNTERSIGN_AXIS.filter((name) => !(name in sdk));
    expect(missing).toEqual([]);
  });

  it('exports the level-axis counterparts it is modelled on', () => {
    const counterparts = [
      'Ed25519Signer',
      'KeyRegistryVerifier',
      'verifyEd25519Signature',
      'computeRecordHash',
      'Level',
    ];
    expect(counterparts.filter((name) => !(name in sdk))).toEqual([]);
  });
});
