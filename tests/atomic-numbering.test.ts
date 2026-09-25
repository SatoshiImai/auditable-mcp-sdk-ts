/** Tests for §7.4 atomic numbering, mirroring the Python SDK's suite. */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { generateToolKey, KeyRegistry, KeyRegistryVerifier, signEvent, type ToolKey } from '../src/l2';
import { type AuditCapability, Countersign, Level, SPEC_VERSION } from '../src/models';
import { AmcpAbortedError, AmcpSession, type EventSigner } from '../src/session';
import { SESSION } from './helpers';

const L2: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L2,
  attempt: 'request',
  countersign: Countersign.NONE,
};
const CONCURRENT = 4;

/**
 * Takes `signer_seq`, then awaits unevenly - the shape of every remote signer (§5.1 KMS).
 *
 * The even-numbered events take longer, so left alone the odd ones overtake them and the tool emits
 * in the opposite order to the one it numbered.
 */
class UnevenSigner implements EventSigner {
  readonly keyId: string;
  readonly #key: ToolKey;

  constructor(key: ToolKey) {
    this.#key = key;
    this.keyId = key.keyId;
  }

  async sign(event: Record<string, unknown>, signerSeq: number): Promise<Record<string, unknown>> {
    // Wait after numbering, which is the order a remote signer works in: the number is fixed before
    // the latency that can reorder the emission.
    await new Promise((resolve) => setTimeout(resolve, signerSeq % 2 === 0 ? 10 : 0));
    return signEvent(event, this.keyId, signerSeq, this.#key.privateKey);
  }
}

function l2Host(): { host: AuditHost; key: ToolKey } {
  const key = generateToolKey('tool-1');
  const registry = new KeyRegistry();
  registry.registerToolKey(key);
  const host = new AuditHost('tenant-a', L2, { verifier: new KeyRegistryVerifier(registry) });
  host.openSession(SESSION);
  return { host, key };
}

async function run(session: AmcpSession, n: number, hold?: Promise<void>): Promise<string> {
  try {
    await using action = await session.action(
      `db.read${n}`,
      { kind: 'table', ref: 'customers' },
      { mutates: false, egress: false },
    );
    await hold;
    action.succeeded();
  } catch (error) {
    return error instanceof AmcpAbortedError ? `aborted:${error.reason}` : 'threw';
  }
  return 'ok';
}

describe('atomic numbering (§7.4)', () => {
  it('concurrent actions emit in the order they were numbered', async () => {
    const { host, key } = l2Host();
    const session = new AmcpSession(new InProcessTransport(host), SESSION, { signer: new UnevenSigner(key) });
    const results = await Promise.all(Array.from({ length: CONCURRENT }, (_, n) => run(session, n)));
    expect(results).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    expect(host.records().map((record) => record.event.signer_seq)).toEqual(
      Array.from({ length: CONCURRENT * 2 }, (_, i) => i),
    );
    expect(host.anomalies()).toEqual([]);
  });

  it('sessions sharing one signer number independently (§7.4)', async () => {
    const { host, key } = l2Host();
    const signer = new UnevenSigner(key);
    const sessions = [SESSION, host.openSession()].map(
      (sessionId) => new AmcpSession(new InProcessTransport(host), sessionId, { signer }),
    );
    const results = await Promise.all(
      Array.from({ length: CONCURRENT }, (_, n) => run(sessions[n % 2] as AmcpSession, n)),
    );
    expect(results).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    for (const session of sessions) {
      const numbers = host
        .records()
        .filter((record) => record.event.session_id === session.sessionId)
        .map((record) => record.event.signer_seq);
      expect(numbers).toEqual(Array.from({ length: CONCURRENT }, (_, i) => i));
    }
    expect(host.anomalies()).toEqual([]);
  });

  it('terminal outcomes are numbered and emitted in one order', async () => {
    const { host, key } = l2Host();
    const session = new AmcpSession(new InProcessTransport(host), SESSION, { signer: new UnevenSigner(key) });
    let release!: () => void;
    // Hold every block until each attempt is in, so only the outcomes race.
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const running = Array.from({ length: CONCURRENT }, (_, n) => run(session, n, held));
    while (host.records().length < CONCURRENT) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    release();
    expect(await Promise.all(running)).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    expect(host.records().map((record) => record.event.signer_seq)).toEqual(
      Array.from({ length: CONCURRENT * 2 }, (_, i) => i),
    );
    expect(host.anomalies()).toEqual([]);
  });

  it('a signer per call from one stored key needs no shared count (§7.4)', async () => {
    // The sequence belongs to the session, so each call's events are 0 and 1 and neither is a replay.
    const { host, key } = l2Host();
    const first = new AmcpSession(new InProcessTransport(host), SESSION, { signer: new UnevenSigner(key) });
    const second = new AmcpSession(new InProcessTransport(host), host.openSession(), {
      signer: new UnevenSigner(key),
    });
    expect([await run(first, 0), await run(second, 1)]).toEqual(['ok', 'ok']);
    expect(host.records().map((record) => record.event.signer_seq)).toEqual([0, 1, 0, 1]);
    expect(host.anomalies()).toEqual([]);
  });

  it('a Level 1 session is not serialized', async () => {
    const host = new AuditHost('tenant-a');
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION);
    const results = await Promise.all(Array.from({ length: CONCURRENT }, (_, n) => run(session, n)));
    expect(results).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    expect(host.records()).toHaveLength(CONCURRENT * 2);
  });
});
