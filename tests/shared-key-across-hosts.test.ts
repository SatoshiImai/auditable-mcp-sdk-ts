/**
 * §7.4: one key shared across hosts and calls leaves a complete sequence in every session.
 *
 * The deployment this covers: a stdio tool with one key, two agents each with its own host, connections
 * alternating. `signer_seq` counts within an audit session (§6.3), and a session is one call recorded by
 * one host, so neither host sees a hole and neither has to be told the key is shared.
 */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { Ed25519Signer, generateToolKey, KeyRegistry, KeyRegistryVerifier } from '../src/l2';
import { Countersign, Level, SPEC_VERSION } from '../src/models';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';

const L2 = { spec_version: SPEC_VERSION, level: Level.L2, attempt: 'request', countersign: Countersign.NONE } as const;

async function twoHostsOneKey(): Promise<[AuditHost, AuditHost]> {
  const key = generateToolKey('janus:menu:ed25519:2026-09-25');
  const registry = new KeyRegistry();
  registry.registerToolKey(key);
  const hosts: [AuditHost, AuditHost] = [
    new AuditHost('agent-x', L2, { verifier: new KeyRegistryVerifier(registry) }),
    new AuditHost('agent-y', L2, { verifier: new KeyRegistryVerifier(registry) }),
  ];
  for (let n = 0; n < 6; n += 1) {
    const host = hosts[n % 2] as AuditHost;
    await host.withSession(async (sessionId) => {
      const session = new AmcpSession(new InProcessTransport(host), sessionId, {
        signer: Ed25519Signer.fromToolKey(key),
      });
      await using action = await session.action(
        'db.read',
        { kind: 'table', ref: 't' },
        { mutates: false, egress: false },
      );
      action.succeeded();
    });
  }
  return hosts;
}

describe('one key shared across hosts (§7.4)', () => {
  it('numbers every session from zero, whichever host recorded it', async () => {
    for (const host of await twoHostsOneKey()) {
      expect(host.records().map((record) => record.event.signer_seq)).toEqual([0, 1, 0, 1, 0, 1]);
    }
  });

  it('leaves neither host with an anomaly', async () => {
    for (const host of await twoHostsOneKey()) {
      expect(host.anomalies()).toEqual([]);
    }
  });

  it('verifies both ledgers without being told the key is shared (§11.4)', async () => {
    for (const host of await twoHostsOneKey()) {
      expect(verifyLedger(host.records()).ok).toBe(true);
    }
  });
});
