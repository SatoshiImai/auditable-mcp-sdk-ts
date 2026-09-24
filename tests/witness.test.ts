/** Tests for the witness axis (§5.2, §7.1, §7.2, §11.4), mirroring the Python SDK's suite. */

import { describe, expect, it } from 'vitest';
import { base64ToBytes } from '../src/crypto/base64';
import { nobleEd25519Engine } from '../src/crypto/noble';
import { computeRecordHash, witnessPayload } from '../src/hashing';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { Ed25519WitnessSigner, generateToolKey, KeyRegistry, SignatureAlgorithm } from '../src/l2';
import { WitnessRegistryVerifier } from '../src/l2/verification';
import type { SealedRecord } from '../src/ledger';
import {
  type AcceptResponse,
  type AttemptResponse,
  type AuditCapability,
  EXTENSION_ID,
  Level,
  SPEC_VERSION,
  Status,
  Witness,
} from '../src/models';
import { AmcpAbortedError, AmcpSession } from '../src/session';
import { type RecordAdapter, verifyLedger } from '../src/verify';
import { FixedDeps, MonotonicClock, makeAttempt } from './helpers';

const HOST_KEY_ID = 'host-key-2026';

function capability(witness: Witness): AuditCapability {
  return { spec_version: SPEC_VERSION, level: Level.L1, attempt: 'request', witness };
}

function signingHost(): { host: AuditHost; publicKey: Uint8Array } {
  const key = generateToolKey(HOST_KEY_ID);
  const host = new AuditHost('tenant-a', capability(Witness.HOST), {
    witnessSigner: new Ed25519WitnessSigner(key.keyId, key.privateKey),
    clock: new MonotonicClock(),
  });
  return { host, publicKey: key.publicKey };
}

function verifierFor(keyId: string, publicKey: Uint8Array): WitnessRegistryVerifier {
  const registry = new KeyRegistry();
  registry.register(keyId, publicKey, SignatureAlgorithm.ED25519);
  return new WitnessRegistryVerifier(registry);
}

/** A host that answers every attempt with one crafted response, so §7.2's order can be exercised. */
class CannedEndpoint {
  readonly outcomes: Record<string, unknown>[] = [];
  readonly #response: AcceptResponse;

  constructor(response: AcceptResponse) {
    this.#response = response;
  }

  get capability(): AuditCapability {
    return capability(Witness.HOST);
  }

  async handleAttempt(): Promise<AttemptResponse> {
    return this.#response;
  }

  async handleOutcome(event: Record<string, unknown>): Promise<void> {
    this.outcomes.push(event);
  }
}

function canned(witness: { host_signature?: string; host_key_id?: string } = {}): AcceptResponse {
  return {
    status: Status.ACCEPT,
    seq: 0,
    record_hash: 'a'.repeat(64),
    host_ts: '2026-07-15T00:00:02.000Z',
    previous_hash: '0'.repeat(64),
    ...witness,
  };
}

async function runOne(session: AmcpSession): Promise<void> {
  await using _action = await session.action(
    'db.read',
    { kind: 'table', ref: 'customers' },
    {
      mutates: false,
      egress: false,
    },
  );
}

describe('the host side of the witness (§7.1, §7.2)', () => {
  it('refuses a host that declares it signs without a signer', () => {
    expect(() => new AuditHost('tenant-a', capability(Witness.HOST))).toThrow(/WitnessSigner/);
  });

  it('returns a verifiable witness on an accept', async () => {
    const { host, publicKey } = signingHost();
    const response = await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'));
    expect(response.status).toBe(Status.ACCEPT);
    const accept = response as AcceptResponse;
    expect(accept.host_key_id).toBe(HOST_KEY_ID);
    const payload = witnessPayload(accept.seq, accept.host_ts, accept.previous_hash, accept.record_hash);
    const signature = new Uint8Array(Buffer.from(accept.host_signature as string, 'base64'));
    expect(nobleEd25519Engine.verify(payload, signature, publicKey)).toBe(true);
  });

  it('returns no witness fields when it declares none', async () => {
    const host = new AuditHost('tenant-a', capability(Witness.NONE), { clock: new MonotonicClock() });
    const accept = (await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'))) as AcceptResponse;
    expect(accept.host_signature).toBeUndefined();
    expect(accept.host_key_id).toBeUndefined();
  });

  it('signs sealed outcome records too, which have no response channel (§7.2)', async () => {
    const { host, publicKey } = signingHost();
    const id = '00000000-0000-4000-8000-000000000001';
    await host.handleAttempt(makeAttempt(id));
    await host.handleOutcome(makeAttempt(id, { outcome: 'success' }));
    const outcomes = host.records().filter((record) => record.event.outcome !== 'attempted');
    expect(outcomes.length).toBeGreaterThan(0);
    for (const record of outcomes) {
      expect(record.host_key_id).toBe(HOST_KEY_ID);
      const payload = witnessPayload(record.seq, record.host_ts, record.previous_hash, record.record_hash);
      const signature = new Uint8Array(Buffer.from(record.host_signature as string, 'base64'));
      expect(nobleEd25519Engine.verify(payload, signature, publicKey)).toBe(true);
    }
  });

  it('does not move the record hash (§5.2, §8.2)', async () => {
    const { host: witnessed } = signingHost();
    const plain = new AuditHost('tenant-a', capability(Witness.NONE), { clock: new MonotonicClock() });
    for (const host of [witnessed, plain]) {
      for (const n of [1, 2, 3]) {
        const id = `00000000-0000-4000-8000-00000000000${n}`;
        await host.handleAttempt(makeAttempt(id));
        await host.handleOutcome(makeAttempt(id, { outcome: 'success' }));
      }
    }
    expect(witnessed.records().map((r) => r.record_hash)).toEqual(plain.records().map((r) => r.record_hash));
    expect(witnessed.digest()).toBe(plain.digest());
    expect(witnessed.records().some((r) => r.host_signature !== undefined)).toBe(true);
    expect(plain.records().every((r) => r.host_signature === undefined)).toBe(true);
  });
});

describe('the tool side of the witness (§7.2)', () => {
  it('refuses requireWitness without a verifier', () => {
    const endpoint = new CannedEndpoint(canned());
    expect(() => new AmcpSession(new InProcessTransport(endpoint), 'call-1', { requireWitness: true })).toThrow(
      /WitnessVerifier/,
    );
  });

  it('aborts host-unwitnessed when a required witness is absent', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned());
    const session = new AmcpSession(new InProcessTransport(endpoint), 'call-1', {
      deps: new FixedDeps(),
      witnessVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
      requireWitness: true,
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes.map((o) => o.reason)).toEqual(['host-unwitnessed']);
  });

  it('aborts host-signature-invalid when a present signature does not verify', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned({ host_signature: 'ZmFrZQ==', host_key_id: HOST_KEY_ID }));
    const session = new AmcpSession(new InProcessTransport(endpoint), 'call-1', {
      deps: new FixedDeps(),
      witnessVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes.map((o) => o.reason)).toEqual(['host-signature-invalid']);
  });

  it('an unknown host key does not establish the witness (§10.9)', async () => {
    const other = generateToolKey('another-host');
    const endpoint = new CannedEndpoint(canned({ host_signature: 'ZmFrZQ==', host_key_id: HOST_KEY_ID }));
    const session = new AmcpSession(new InProcessTransport(endpoint), 'call-1', {
      deps: new FixedDeps(),
      witnessVerifier: verifierFor('another-host', other.publicKey),
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes[0]?.reason).toBe('host-signature-invalid');
  });

  it('an absent witness precedes a hash mismatch (§7.2)', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned());
    const session = new AmcpSession(new InProcessTransport(endpoint), 'call-1', {
      deps: new FixedDeps(),
      pollutedStop: true,
      witnessVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
      requireWitness: true,
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes[0]?.reason).toBe('host-unwitnessed');
  });

  it('an invalid witness precedes a hash mismatch (§7.2)', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned({ host_signature: 'ZmFrZQ==', host_key_id: HOST_KEY_ID }));
    const session = new AmcpSession(new InProcessTransport(endpoint), 'call-1', {
      deps: new FixedDeps(),
      pollutedStop: true,
      witnessVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
      requireWitness: true,
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes[0]?.reason).toBe('host-signature-invalid');
  });
});

describe('the verifier side of the witness (§11.4)', () => {
  async function witnessedChain(): Promise<{ records: SealedRecord[]; publicKey: Uint8Array }> {
    const { host, publicKey } = signingHost();
    for (const n of [1, 2, 3]) {
      const id = `00000000-0000-4000-8000-00000000000${n}`;
      await host.handleAttempt(makeAttempt(id));
      await host.handleOutcome(makeAttempt(id, { outcome: 'success' }));
    }
    return { records: host.records(), publicKey };
  }

  it('confirms every witness when it holds the registry', async () => {
    const { records, publicKey } = await witnessedChain();
    const report = verifyLedger(records, undefined, undefined, undefined, verifierFor(HOST_KEY_ID, publicKey).check);
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual([]);
    expect(report.complete).toBe(true);
  });

  it('says it did not check when it holds no registry', async () => {
    const { records } = await witnessedChain();
    const report = verifyLedger(records);
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['witness']);
    expect(report.complete).toBe(false);
  });

  it('reports nothing unchecked for a chain with no witness', async () => {
    const host = new AuditHost('tenant-a', capability(Witness.NONE), { clock: new MonotonicClock() });
    await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'));
    const report = verifyLedger(host.records());
    expect(report.unchecked).toEqual([]);
    expect(report.complete).toBe(true);
  });

  it('flags a witness that does not verify', async () => {
    const { records } = await witnessedChain();
    const stranger = generateToolKey(HOST_KEY_ID);
    const report = verifyLedger(
      records,
      undefined,
      undefined,
      undefined,
      verifierFor(HOST_KEY_ID, stranger.publicKey).check,
    );
    expect(report.ok).toBe(false);
    expect(new Set(report.issues.map((issue) => issue.kind))).toEqual(new Set(['host-signature-invalid']));
  });
});

/** A signer whose backend is down, as an HSM or KMS client would be. */
class FailingSigner {
  readonly keyId = HOST_KEY_ID;
  async sign(): Promise<string> {
    throw new Error('KMS unreachable');
  }
}

describe('the implementation review’s findings (§5.1, §7.1, §11.4)', () => {
  it('ships the SEP-2133 extension identifier', () => {
    expect(EXTENSION_ID).toBe('com.timberlandchapel/auditable-mcp');
  });

  it('refuses a host that declares none and holds a signer (§7.1)', () => {
    expect(() => new AuditHost('tenant-a', capability(Witness.NONE), { witnessSigner: new FailingSigner() })).toThrow(
      /must not hold/,
    );
  });

  it('fails closed as unavailable when the signer fails (§7.1, §7.6)', async () => {
    const host = new AuditHost('tenant-a', capability(Witness.HOST), {
      witnessSigner: new FailingSigner(),
      clock: new MonotonicClock(),
    });
    const response = await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'));
    expect(response.status).toBe(Status.UNAVAILABLE);
    expect(host.records()).toEqual([]);
  });

  it('names an unverified Level-2 signature as unchecked (§11.4)', async () => {
    const host = new AuditHost('tenant-a', capability(Witness.NONE), { clock: new MonotonicClock() });
    await host.handleAttempt(
      makeAttempt('00000000-0000-4000-8000-000000000001', { key_id: 'k1', signer_seq: 1, signature: 'ZmFrZQ==' }),
    );
    const report = verifyLedger(host.records());
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['level-2-signature']);
    expect(report.complete).toBe(false);
  });

  it('reports a stored half pair rather than ignoring it (§7.1)', () => {
    const event = makeAttempt('00000000-0000-4000-8000-000000000001');
    const recordHash = computeRecordHash(event, 0, '2026-07-15T00:00:02.000Z', '0'.repeat(64));
    for (const witness of [{ host_signature: 'ZmFrZQ==' }, { host_key_id: HOST_KEY_ID }]) {
      const record: SealedRecord = {
        event,
        seq: 0,
        host_ts: '2026-07-15T00:00:02.000Z',
        previous_hash: '0'.repeat(64),
        record_hash: recordHash,
        ...witness,
      };
      const report = verifyLedger([record]);
      expect(report.ok, JSON.stringify(witness)).toBe(false);
      expect(report.issues.map((issue) => issue.kind)).toEqual(['host-signature-invalid']);
    }
  });

  it('decodes only standard base64, as §5.1 pins it (RFC 4648 §4)', () => {
    expect(base64ToBytes('ZmFrZQ==')).toHaveLength(4);
    for (const malformed of ['Zm Fr ZQ==', 'ZmFrZQ', 'a-_b', 'ZmFr!ZQ==']) {
      expect(() => base64ToBytes(malformed), malformed).toThrow();
    }
  });
});

describe('the overview review’s findings (§10.10, §11.4)', () => {
  function enveloped(inner: Record<string, unknown>): { record: SealedRecord; adapter: RecordAdapter } {
    const envelope = { principal_id: 'tenant-a', extensions: { 'auditable-mcp': inner } };
    const recordHash = computeRecordHash(envelope, 0, '2026-07-15T00:00:02.000Z', '0'.repeat(64));
    const reach = (event: Record<string, unknown>): Record<string, unknown> =>
      (event.extensions as Record<string, Record<string, unknown>>)['auditable-mcp'] as Record<string, unknown>;
    return {
      record: {
        event: envelope,
        seq: 0,
        host_ts: '2026-07-15T00:00:02.000Z',
        previous_hash: '0'.repeat(64),
        record_hash: recordHash,
      },
      adapter: {
        idOf: (event) => reach(event).id,
        isAttempt: (event) => reach(event).outcome === 'attempted',
        eventOf: reach,
        principalOf: (event) => event.principal_id,
      },
    };
  }

  it('names an enveloped Level-2 signature as unchecked too (§11.4)', () => {
    const inner = makeAttempt('00000000-0000-4000-8000-000000000001', {
      key_id: 'k1',
      signer_seq: 1,
      signature: 'ZmFrZQ==',
    });
    const { record, adapter } = enveloped(inner);
    const report = verifyLedger([record], undefined, adapter, 'tenant-a');
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['level-2-signature']);
    expect(report.complete).toBe(false);
  });

  it('keeps `unchecked` when the schema branch also fires (§11.4)', () => {
    const badEvent = { not: 'an audit event' };
    const record: SealedRecord = {
      event: badEvent,
      seq: 0,
      host_ts: '2026-07-15T00:00:02.000Z',
      previous_hash: '0'.repeat(64),
      record_hash: computeRecordHash(badEvent, 0, '2026-07-15T00:00:02.000Z', '0'.repeat(64)),
      host_signature: 'ZmFrZQ==',
      host_key_id: HOST_KEY_ID,
    };
    const report = verifyLedger([record]);
    expect(report.ok).toBe(false);
    expect(report.issues.some((issue) => issue.kind === 'schema-invalid')).toBe(true);
    expect(report.unchecked).toEqual(['witness']);
  });
});
