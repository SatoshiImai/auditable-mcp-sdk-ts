/** Host and session rules revised in v0.3's adversarial review (§6.3, §7.1, §7.2, §7.4, §8.1). */

import { describe, expect, it } from 'vitest';
import type { NegotiationResult } from '../src/capability';
import { negotiate } from '../src/capability';
import { countersignaturePayload } from '../src/hashing';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  CountersignatureRegistryVerifier,
  Ed25519Countersigner,
  generateToolKey,
  KeyRegistry,
  KeyRole,
  SignatureAlgorithm,
} from '../src/l2';
import type { SealedRecord } from '../src/ledger';
import {
  type AttemptResponse,
  type AuditCapability,
  Countersign,
  firstValidationError,
  Level,
  SPEC_VERSION,
} from '../src/models';
import { AmcpAbortedError, AmcpSession, SessionNumbering } from '../src/session';
import { InMemoryLedgerRepository, RepositoryError } from '../src/storage';
import { type AuditTransport, accept } from '../src/transport';
import {
  eventIdAt,
  FixedDeps,
  L2_CAPABILITY,
  MonotonicClock,
  makeAttempt,
  OkVerifier,
  SESSION,
  signed,
} from './helpers';

const TABLE = { kind: 'table', ref: 'orders' };
const L1: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};

function l2Host(): AuditHost {
  const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
  host.openSession(SESSION);
  return host;
}

function kinds(host: AuditHost): string[] {
  return host.anomalies().map((anomaly) => anomaly.kind);
}

describe('a tool that requires a countersignature performs Polluted Stop at either level (§7.2)', () => {
  it('a genuine countersigned accept for another record is refused as hash-mismatch under Level 1', async () => {
    const hostKey = generateToolKey('host-1');
    const registry = new KeyRegistry(KeyRole.HOST);
    registry.register(hostKey.keyId, hostKey.publicKey, SignatureAlgorithm.ED25519);
    const countersigner = new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey);
    // A real accept the host issued for some other record, replayed into this exchange.
    const hostTs = '2026-07-15T00:00:01.000Z';
    const signature = await countersigner.sign(
      countersignaturePayload(0, hostTs, 'tenant-a', '0'.repeat(64), 'b'.repeat(64)),
    );
    let performed = false;
    const transport: AuditTransport = {
      negotiate: (offered): NegotiationResult => negotiate(offered, offered),
      sendAttempt: async (): Promise<AttemptResponse> =>
        accept(0, 'b'.repeat(64), hostTs, '0'.repeat(64), {
          hostSignature: signature,
          hostKeyId: hostKey.keyId,
          logId: 'tenant-a',
        }),
      sendOutcome: async () => {},
    };
    const session = new AmcpSession(transport, SESSION, {
      deps: new FixedDeps(),
      requireCountersign: true,
      countersignatureVerifier: new CountersignatureRegistryVerifier(registry),
    });
    const acting = async (): Promise<void> => {
      await using action = await session.action('db.read', TABLE, { mutates: false, egress: false });
      performed = true;
      action.succeeded();
    };
    await expect(acting()).rejects.toMatchObject({ reason: 'hash-mismatch' });
    expect(performed).toBe(false);
  });

  it('switching Polluted Stop off while requiring a countersignature is refused', () => {
    const registry = new KeyRegistry(KeyRole.HOST);
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock() });
    expect(
      () =>
        new AmcpSession(new InProcessTransport(host), SESSION, {
          requireCountersign: true,
          pollutedStop: false,
          countersignatureVerifier: new CountersignatureRegistryVerifier(registry),
        }),
    ).toThrow(/Polluted Stop/);
  });
});

describe('the replay window is the set of decided signer_seq values (§7.4)', () => {
  it('a value below one decided, and not itself decided, is accepted after unavailable', async () => {
    const host = l2Host();
    host.persistenceAvailable = false;
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0))).status).toBe('unavailable');
    host.persistenceAvailable = true;
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 1))).status).toBe('accept');
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0))).status).toBe('accept');
  });

  it('a value already decided is refused, whatever came after it', async () => {
    const host = l2Host();
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0))).status).toBe('accept');
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 2))).status).toBe('accept');
    expect(await host.handleAttempt(signed(makeAttempt(eventIdAt(3)), 0))).toEqual({
      status: 'reject',
      reason: 'replay-detected',
    });
  });
});

describe('outcome validation runs in attempt order, then correlation (§7.2)', () => {
  it('a forged orphan is recorded signature-invalid, not orphaned-outcome', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: { verify: async () => 'signature-invalid' },
      clock: new MonotonicClock(),
    });
    host.openSession(SESSION);
    await host.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'success' }), 0));
    expect(kinds(host)).toEqual(['signature-invalid']);
  });

  it('an unsigned or unknown-key outcome is recorded signature-invalid', async () => {
    const unknown = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: { verify: async () => 'unknown-key' },
      clock: new MonotonicClock(),
    });
    unknown.openSession(SESSION);
    await unknown.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-rejected' }), 0));
    expect(kinds(unknown)).toEqual(['signature-invalid']);

    const host = l2Host();
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-rejected' }));
    expect(kinds(host)).toEqual(['signature-invalid']);
    expect(host.records()).toEqual([]);
  });

  it('an outcome of another session is recorded replay-detected', async () => {
    const host = l2Host();
    const other = host.openSession();
    await host.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'success', session_id: other }), 0), SESSION);
    expect(kinds(host)).toEqual(['replay-detected']);
  });

  it('one terminal outcome per operation: a differing second one is replay-detected, a repeat is ignored', async () => {
    const host = l2Host();
    const attempt = signed(makeAttempt(eventIdAt(1)), 0);
    await host.handleAttempt(attempt);
    const success = signed(makeAttempt(eventIdAt(1), { outcome: 'success' }), 1);
    await host.handleOutcome(success);
    await host.handleOutcome(success);
    await host.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'failed' }), 2));
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(kinds(host)).toEqual(['replay-detected']);
  });

  it('an outcome correlates within its own session only', async () => {
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const other = host.openSession();
    await host.handleAttempt(makeAttempt(eventIdAt(1)));
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'success', session_id: other }));
    expect(kinds(host)).toEqual(['orphaned-outcome']);
  });
});

describe('the host issues each session id once, ever (§6.3)', () => {
  it('a closed session id is not issued again', async () => {
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock() });
    const issued = host.openSession();
    await host.closeSession(issued);
    expect(() => host.openSession(issued)).toThrow(/already issued/);
  });
});

describe('the session numbering is shared through the transport (§7.4)', () => {
  it('two AmcpSessions over one transport number one sequence', async () => {
    const host = l2Host();
    const numbering = new SessionNumbering();
    const inner = new InProcessTransport(host);
    const transport = {
      numbering,
      negotiate: (offered: AuditCapability) => inner.negotiate(offered),
      sendAttempt: (event: Record<string, unknown>) => inner.sendAttempt(event),
      sendOutcome: (event: Record<string, unknown>) => inner.sendOutcome(event),
    };
    const signer = {
      keyId: 'k1',
      sign: async (event: Record<string, unknown>, signerSeq: number) => signed(event, signerSeq),
    };
    const deps = new FixedDeps();
    for (let n = 0; n < 2; n += 1) {
      const session = new AmcpSession(transport, SESSION, { signer, deps, pollutedStop: true });
      await using action = await session.action('db.read', TABLE, { mutates: false, egress: false });
      action.succeeded();
    }
    expect(host.records().map((record) => record.event.signer_seq)).toEqual([0, 1, 2, 3]);
    expect(host.anomalies()).toEqual([]);
    expect(numbering.next).toBe(4);
  });
});

describe('lone surrogates are schema-invalid (§8.1)', () => {
  it('in a value and in a member name', async () => {
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const inValue = makeAttempt(eventIdAt(1), { action_context: { note: 'a\uD800b' } });
    const inKey = makeAttempt(eventIdAt(2), { action_context: { '\uDC00': 1 } });
    expect(firstValidationError(inValue)).toMatch(/surrogate/);
    expect(await host.handleAttempt(inValue)).toEqual({ status: 'reject', reason: 'schema-invalid' });
    expect(await host.handleAttempt(inKey)).toEqual({ status: 'reject', reason: 'schema-invalid' });
    await host.handleOutcome(
      makeAttempt(eventIdAt(3), { outcome: 'aborted', reason: 'host-rejected', traceparent: '\uD83D' }),
    );
    expect(kinds(host)).toEqual(['schema-invalid', 'schema-invalid', 'schema-invalid']);
    expect(firstValidationError(makeAttempt(eventIdAt(4), { action_context: { note: '😀' } }))).toBeNull();
  });
});

/** Fails `append` once after writing the record: the write landed, and the caller cannot tell. */
class AmbiguousRepository extends InMemoryLedgerRepository {
  landButFail = false;
  override async append(partition: string, record: SealedRecord): Promise<void> {
    await super.append(partition, record);
    if (this.landButFail) {
      this.landButFail = false;
      throw new RepositoryError('timed out after the write');
    }
  }
}

describe('an ambiguous persistence failure is settled from the stored tail (§7.1)', () => {
  it('a record that did land is adopted, not sealed a second time at its seq', async () => {
    const repository = new AmbiguousRepository();
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock(), repository });
    host.openSession(SESSION);
    repository.landButFail = true;
    const first = makeAttempt(eventIdAt(1));
    expect((await host.handleAttempt(first)).status).toBe('unavailable');
    // The identical attempt again is answered from the record that landed.
    expect(await host.handleAttempt(first)).toMatchObject({ status: 'accept', seq: 0 });
    expect((await host.handleAttempt(makeAttempt(eventIdAt(2)))).status).toBe('accept');
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'success' }));
    const stored = await repository.readAll('tenant-a');
    expect(stored.map((record) => record.seq)).toEqual([0, 1, 2]);
    expect(host.digest()).toBe(stored[2]?.record_hash);
    await host.closeSession(SESSION);
    expect(kinds(host)).toEqual(['unresolved-attempt']);
  });
});

describe('AmcpAbortedError is still the fail-closed signal', () => {
  it('is exported for the tests above', () => {
    expect(new AmcpAbortedError('a', 'b', 'c').reason).toBe('c');
  });
});

describe('an outcome dropped after its signature verified is decided (§7.4)', () => {
  it('an outcome lost to a persistence failure is not decided, as unavailable is not', async () => {
    const host = l2Host();
    await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0));
    host.persistenceAvailable = false;
    const outcome = signed(makeAttempt(eventIdAt(1), { outcome: 'success' }), 1);
    await host.handleOutcome(outcome);
    host.persistenceAvailable = true;
    await host.handleOutcome({ ...outcome });
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(host.anomalies()).toEqual([]);
  });

  it('an orphan is decided too', async () => {
    const host = l2Host();
    await host.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'success' }), 0));
    expect(await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 0))).toEqual({
      status: 'reject',
      reason: 'replay-detected',
    });
    expect(kinds(host)).toEqual(['orphaned-outcome', 'replay-detected']);
  });
});

describe('a byte-identical outcome repeat is disposed of before the sequence check (§7.2, §7.4)', () => {
  it('the repeat under Level 2 records no anomaly and seals nothing', async () => {
    const host = l2Host();
    await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0));
    const success = signed(makeAttempt(eventIdAt(1), { outcome: 'success' }), 1);
    await host.handleOutcome(success);
    await host.handleOutcome(success);
    expect(host.records()).toHaveLength(2);
    expect(kinds(host)).toEqual([]);
  });
});

describe('no attempt is sealed after its operation concluded (§7.1 rule 4)', () => {
  it('an attempt answered unavailable, then refused, and sent again is replay-detected', async () => {
    const host = l2Host();
    const attempt = signed(makeAttempt(eventIdAt(1)), 0);
    host.persistenceAvailable = false;
    expect((await host.handleAttempt(attempt)).status).toBe('unavailable');
    host.persistenceAvailable = true;
    await host.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-unavailable' }), 1));
    expect(await host.handleAttempt(attempt)).toEqual({ status: 'reject', reason: 'replay-detected' });
    expect(host.records().map((record) => record.event.outcome)).toEqual(['aborted']);
    expect(kinds(host)).toEqual(['replay-detected']);
  });

  it('a byte-identical repeat of a sealed attempt is still answered from the ledger after its outcome', async () => {
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const attempt = makeAttempt(eventIdAt(1));
    const first = await host.handleAttempt(attempt);
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'success' }));
    expect(await host.handleAttempt(attempt)).toEqual(first);
    expect(kinds(host)).toEqual([]);
  });
});

describe('an attempt refused for its signature is recorded under a Tier-1 anomaly kind (§7.6)', () => {
  it('unknown-key and l2-unsigned are reject reasons; the anomaly is signature-invalid', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: { verify: async () => 'unknown-key' },
      clock: new MonotonicClock(),
    });
    host.openSession(SESSION);
    expect(await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0))).toEqual({
      status: 'reject',
      reason: 'unknown-key',
    });
    expect(await host.handleAttempt(makeAttempt(eventIdAt(2)))).toEqual({ status: 'reject', reason: 'l2-unsigned' });
    expect(kinds(host)).toEqual(['signature-invalid', 'signature-invalid']);
  });
});

describe('an item where an outcome belongs that is not an event is recorded (§6.4)', () => {
  it('null, a string, and an array are each schema-invalid', async () => {
    const host = new AuditHost('tenant-a', L1, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    for (const item of [null, 'event', [makeAttempt(eventIdAt(1), { outcome: 'success' })]]) {
      await host.handleOutcome(item, SESSION);
    }
    expect(kinds(host)).toEqual(['schema-invalid', 'schema-invalid', 'schema-invalid']);
    expect(host.records()).toEqual([]);
  });
});
