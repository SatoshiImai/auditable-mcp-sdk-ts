/** Tests for §7.4 atomic numbering, mirroring the Python SDK's suite. */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { generateToolKey, KeyRegistry, KeyRegistryVerifier, signEvent, type ToolKey } from '../src/l2';
import { type AuditCapability, Level, SPEC_VERSION, Witness } from '../src/models';
import { AmcpAbortedError, AmcpSession, type EventSigner } from '../src/session';

const L2: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L2,
  attempt: 'request',
  witness: Witness.NONE,
};
const CONCURRENT = 4;

/**
 * Takes `signer_seq`, then awaits unevenly - the shape of every remote signer (§5.1 KMS).
 *
 * The even-numbered events take longer, so left alone the odd ones overtake them and the tool emits
 * in the opposite order to the one it numbered.
 */
class UnevenSigner implements EventSigner {
  #next = 0;
  readonly #key: ToolKey;

  constructor(key: ToolKey) {
    this.#key = key;
  }

  async sign(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    const signerSeq = this.#next;
    this.#next += 1;
    await new Promise((resolve) => setTimeout(resolve, signerSeq % 2 === 0 ? 10 : 0));
    return signEvent(event, this.#key.keyId, signerSeq, this.#key.privateKey);
  }
}

function l2Host(): { host: AuditHost; key: ToolKey } {
  const key = generateToolKey('tool-1');
  const registry = new KeyRegistry();
  registry.registerToolKey(key);
  return { host: new AuditHost('tenant-a', L2, { verifier: new KeyRegistryVerifier(registry) }), key };
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
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', { signer: new UnevenSigner(key) });
    const results = await Promise.all(Array.from({ length: CONCURRENT }, (_, n) => run(session, n)));
    expect(results).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    expect(host.records().map((record) => record.event.signer_seq)).toEqual(
      Array.from({ length: CONCURRENT * 2 }, (_, i) => i),
    );
    expect(host.anomalies()).toEqual([]);
  });

  it('sessions sharing one signer share the section', async () => {
    const { host, key } = l2Host();
    const signer = new UnevenSigner(key);
    const sessions = [0, 1].map((n) => new AmcpSession(new InProcessTransport(host), `call-${n}`, { signer }));
    const results = await Promise.all(
      Array.from({ length: CONCURRENT }, (_, n) => run(sessions[n % 2] as AmcpSession, n)),
    );
    expect(results).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    expect(host.records().map((record) => record.event.signer_seq)).toEqual(
      Array.from({ length: CONCURRENT * 2 }, (_, i) => i),
    );
    expect(host.anomalies()).toEqual([]);
  });

  it('terminal outcomes are numbered and emitted in one order', async () => {
    const { host, key } = l2Host();
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', { signer: new UnevenSigner(key) });
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

  it('a Level 1 session is not serialized', async () => {
    const host = new AuditHost('tenant-a');
    const session = new AmcpSession(new InProcessTransport(host), 'call-1');
    const results = await Promise.all(Array.from({ length: CONCURRENT }, (_, n) => run(session, n)));
    expect(results).toEqual(Array.from({ length: CONCURRENT }, () => 'ok'));
    expect(host.records()).toHaveLength(CONCURRENT * 2);
  });
});
