/** Tests for the countersign axis (§5.2, §7.1, §7.2, §11.4), mirroring the Python SDK's suite. */

import { describe, expect, it } from 'vitest';
import { base64urlToBytes } from '../src/crypto/base64';
import { nobleEd25519Engine } from '../src/crypto/noble';
import { computeRecordHash, countersignaturePayload } from '../src/hashing';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { Ed25519Countersigner, generateToolKey, KeyRegistry, KeyRole, SignatureAlgorithm } from '../src/l2';
import { CountersignatureRegistryVerifier, KeyRegistryVerifier } from '../src/l2/verification';
import type { SealedRecord } from '../src/ledger';
import {
  type AcceptResponse,
  type AttemptResponse,
  type AuditCapability,
  Countersign,
  EXTENSION_ID,
  Level,
  SPEC_VERSION,
  Status,
} from '../src/models';
import { AmcpAbortedError, AmcpSession } from '../src/session';
import { AmcpUsageError } from '../src/transport';
import { type RecordAdapter, verifyLedger } from '../src/verify';
import { FixedDeps, LOG_ID, MonotonicClock, makeAttempt, SESSION, StubEndpoint } from './helpers';

const HOST_KEY_ID = 'host-key-2026';

function capability(countersign: Countersign): AuditCapability {
  return { spec_version: SPEC_VERSION, level: Level.L1, attempt: 'request', countersign };
}

function signingHost(): { host: AuditHost; publicKey: Uint8Array } {
  const key = generateToolKey(HOST_KEY_ID);
  const host = new AuditHost('tenant-a', capability(Countersign.HOST), {
    countersigner: new Ed25519Countersigner(key.keyId, key.privateKey),
    clock: new MonotonicClock(),
  });
  host.openSession(SESSION);
  return { host, publicKey: key.publicKey };
}

function verifierFor(keyId: string, publicKey: Uint8Array): CountersignatureRegistryVerifier {
  const registry = new KeyRegistry(KeyRole.HOST);
  registry.register(keyId, publicKey, SignatureAlgorithm.ED25519);
  return new CountersignatureRegistryVerifier(registry);
}

/** A host that answers every attempt with one crafted response, so §7.2's order can be exercised. */
class CannedEndpoint extends StubEndpoint {
  readonly outcomes: Record<string, unknown>[] = [];
  readonly #response: AcceptResponse;

  constructor(response: AcceptResponse) {
    super();
    this.#response = response;
  }

  get capability(): AuditCapability {
    return capability(Countersign.HOST);
  }

  async handleAttempt(): Promise<AttemptResponse> {
    return this.#response;
  }

  async handleOutcome(event: Record<string, unknown>): Promise<void> {
    this.outcomes.push(event);
  }
}

function canned(countersign: { host_signature?: string; host_key_id?: string } = {}): AcceptResponse {
  return {
    status: Status.ACCEPT,
    seq: 0,
    record_hash: 'a'.repeat(64),
    host_ts: '2026-07-15T00:00:02.000Z',
    previous_hash: '0'.repeat(64),
    ...countersign,
    ...(countersign.host_signature === undefined ? {} : { log_id: LOG_ID }),
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

describe('the host side of the countersign (§7.1, §7.2)', () => {
  it('refuses a host that declares it signs without a signer', () => {
    expect(() => new AuditHost('tenant-a', capability(Countersign.HOST))).toThrow(/Countersigner/);
  });

  it('returns a verifiable countersign on an accept', async () => {
    const { host, publicKey } = signingHost();
    const response = await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'));
    expect(response.status).toBe(Status.ACCEPT);
    const accept = response as AcceptResponse;
    expect(accept.host_key_id).toBe(HOST_KEY_ID);
    const payload = countersignaturePayload(
      accept.seq,
      accept.host_ts,
      LOG_ID,
      accept.previous_hash,
      accept.record_hash,
    );
    const signature = new Uint8Array(Buffer.from(accept.host_signature as string, 'base64'));
    expect(nobleEd25519Engine.verify(payload, signature, publicKey)).toBe(true);
  });

  it('returns no countersign fields when it declares none', async () => {
    const host = new AuditHost('tenant-a', capability(Countersign.NONE), { clock: new MonotonicClock() });
    host.openSession(SESSION);
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
      const payload = countersignaturePayload(
        record.seq,
        record.host_ts,
        LOG_ID,
        record.previous_hash,
        record.record_hash,
      );
      const signature = new Uint8Array(Buffer.from(record.host_signature as string, 'base64'));
      expect(nobleEd25519Engine.verify(payload, signature, publicKey)).toBe(true);
    }
  });

  it('does not move the record hash (§5.2, §8.2)', async () => {
    const { host: countersigned } = signingHost();
    const plain = new AuditHost('tenant-a', capability(Countersign.NONE), { clock: new MonotonicClock() });
    plain.openSession(SESSION);
    for (const host of [countersigned, plain]) {
      for (const n of [1, 2, 3]) {
        const id = `00000000-0000-4000-8000-00000000000${n}`;
        await host.handleAttempt(makeAttempt(id));
        await host.handleOutcome(makeAttempt(id, { outcome: 'success' }));
      }
    }
    expect(countersigned.records().map((r) => r.record_hash)).toEqual(plain.records().map((r) => r.record_hash));
    expect(countersigned.digest()).toBe(plain.digest());
    expect(countersigned.records().some((r) => r.host_signature !== undefined)).toBe(true);
    expect(plain.records().every((r) => r.host_signature === undefined)).toBe(true);
  });
});

describe('the tool side of the countersign (§7.2)', () => {
  it('refuses requireCountersign without a verifier', () => {
    const endpoint = new CannedEndpoint(canned());
    expect(() => new AmcpSession(new InProcessTransport(endpoint), SESSION, { requireCountersign: true })).toThrow(
      /CountersignatureVerifier/,
    );
  });

  it('aborts host-uncountersigned when a required countersign is absent', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned());
    const session = new AmcpSession(new InProcessTransport(endpoint), SESSION, {
      deps: new FixedDeps(),
      countersignatureVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
      requireCountersign: true,
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes.map((o) => o.reason)).toEqual(['host-uncountersigned']);
  });

  it('aborts host-signature-invalid when a present signature does not verify', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned({ host_signature: 'ZmFrZQ', host_key_id: HOST_KEY_ID }));
    const session = new AmcpSession(new InProcessTransport(endpoint), SESSION, {
      deps: new FixedDeps(),
      countersignatureVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes.map((o) => o.reason)).toEqual(['host-signature-invalid']);
  });

  it('an unknown host key does not establish the countersign (§10.9)', async () => {
    const other = generateToolKey('another-host');
    const endpoint = new CannedEndpoint(canned({ host_signature: 'ZmFrZQ', host_key_id: HOST_KEY_ID }));
    const session = new AmcpSession(new InProcessTransport(endpoint), SESSION, {
      deps: new FixedDeps(),
      countersignatureVerifier: verifierFor('another-host', other.publicKey),
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes[0]?.reason).toBe('host-signature-invalid');
  });

  it('an absent countersign precedes a hash mismatch (§7.2)', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned());
    const session = new AmcpSession(new InProcessTransport(endpoint), SESSION, {
      deps: new FixedDeps(),
      pollutedStop: true,
      countersignatureVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
      requireCountersign: true,
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes[0]?.reason).toBe('host-uncountersigned');
  });

  it('an invalid countersign precedes a hash mismatch (§7.2)', async () => {
    const key = generateToolKey(HOST_KEY_ID);
    const endpoint = new CannedEndpoint(canned({ host_signature: 'ZmFrZQ', host_key_id: HOST_KEY_ID }));
    const session = new AmcpSession(new InProcessTransport(endpoint), SESSION, {
      deps: new FixedDeps(),
      pollutedStop: true,
      countersignatureVerifier: verifierFor(HOST_KEY_ID, key.publicKey),
      requireCountersign: true,
    });
    await expect(runOne(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes[0]?.reason).toBe('host-signature-invalid');
  });
});

describe('the verifier side of the countersign (§11.4)', () => {
  async function countersignedChain(): Promise<{ records: SealedRecord[]; publicKey: Uint8Array }> {
    const { host, publicKey } = signingHost();
    for (const n of [1, 2, 3]) {
      const id = `00000000-0000-4000-8000-00000000000${n}`;
      await host.handleAttempt(makeAttempt(id));
      await host.handleOutcome(makeAttempt(id, { outcome: 'success' }));
    }
    return { records: host.records(), publicKey };
  }

  it('confirms every countersign when it holds the registry', async () => {
    const { records, publicKey } = await countersignedChain();
    const report = verifyLedger(records, undefined, undefined, undefined, verifierFor(HOST_KEY_ID, publicKey).check);
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual([]);
    expect(report.complete).toBe(true);
  });

  it('says it did not check when it holds no registry', async () => {
    const { records } = await countersignedChain();
    const report = verifyLedger(records);
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['countersignature']);
    expect(report.complete).toBe(false);
  });

  it('reports nothing unchecked for a chain with no countersign', async () => {
    const host = new AuditHost('tenant-a', capability(Countersign.NONE), { clock: new MonotonicClock() });
    host.openSession(SESSION);
    await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'));
    const report = verifyLedger(host.records());
    expect(report.unchecked).toEqual([]);
    expect(report.complete).toBe(true);
  });

  it('takes every input by name as an options object', async () => {
    const { records, publicKey } = await countersignedChain();
    const checker = verifierFor(HOST_KEY_ID, publicKey).check;
    const report = verifyLedger(records, {
      countersignatureChecker: checker,
      countersignatureRequired: true,
      expectedIdentity: { logId: LOG_ID, hostKeyIds: new Set([HOST_KEY_ID]) },
    });
    expect(report.ok).toBe(true);
    expect(report.complete).toBe(true);

    const elsewhere = verifyLedger(records, {
      countersignatureChecker: checker,
      expectedIdentity: { logId: 'tenant-b', hostKeyIds: new Set([HOST_KEY_ID]) },
    });
    expect(new Set(elsewhere.issues.map((issue) => issue.kind))).toEqual(new Set(['principal-mismatch']));
  });

  it('refuses a verifier object where a checker function belongs, naming the method to pass', async () => {
    const { records, publicKey } = await countersignedChain();
    const verifier = verifierFor(HOST_KEY_ID, publicKey);
    const registry = new KeyRegistry(KeyRole.TOOL);
    registry.register('tool-k1', generateToolKey('tool-k1').publicKey, SignatureAlgorithm.ED25519);
    const toolVerifier = new KeyRegistryVerifier(registry);

    expect(() => verifyLedger(records, { countersignatureChecker: verifier as never })).toThrow(AmcpUsageError);
    expect(() => verifyLedger(records, { countersignatureChecker: verifier as never })).toThrow(
      /CountersignatureRegistryVerifier\.check/,
    );
    expect(() => verifyLedger(records, { signatureChecker: toolVerifier as never })).toThrow(
      /KeyRegistryVerifier\.check/,
    );
    expect(() => verifyLedger(records, undefined, undefined, undefined, verifier as never)).toThrow(AmcpUsageError);
  });

  it('flags a countersign that does not verify', async () => {
    const { records } = await countersignedChain();
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
    expect(
      () => new AuditHost('tenant-a', capability(Countersign.NONE), { countersigner: new FailingSigner() }),
    ).toThrow(/must not hold/);
  });

  it('fails closed as unavailable when the signer fails (§7.1, §7.6)', async () => {
    const host = new AuditHost('tenant-a', capability(Countersign.HOST), {
      countersigner: new FailingSigner(),
      clock: new MonotonicClock(),
    });
    host.openSession(SESSION);
    const response = await host.handleAttempt(makeAttempt('00000000-0000-4000-8000-000000000001'));
    expect(response.status).toBe(Status.UNAVAILABLE);
    expect(host.records()).toEqual([]);
  });

  it('names an unverified Level-2 signature as unchecked (§11.4)', async () => {
    const host = new AuditHost('tenant-a', capability(Countersign.NONE), { clock: new MonotonicClock() });
    host.openSession(SESSION);
    await host.handleAttempt(
      makeAttempt('00000000-0000-4000-8000-000000000001', { key_id: 'k1', signer_seq: 0, signature: 'ZmFrZQ' }),
    );
    const report = verifyLedger(host.records());
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['level-2-signature']);
    expect(report.complete).toBe(false);
  });

  it('reports a stored partial triple rather than ignoring it (§7.1)', () => {
    const event = makeAttempt('00000000-0000-4000-8000-000000000001');
    const recordHash = computeRecordHash(event, 0, '2026-07-15T00:00:02.000Z', '0'.repeat(64));
    const partial = [
      { host_signature: 'ZmFrZQ' },
      { host_key_id: HOST_KEY_ID },
      { log_id: LOG_ID },
      { host_signature: 'ZmFrZQ', host_key_id: HOST_KEY_ID },
    ];
    for (const countersign of partial) {
      const record: SealedRecord = {
        event,
        seq: 0,
        host_ts: '2026-07-15T00:00:02.000Z',
        previous_hash: '0'.repeat(64),
        record_hash: recordHash,
        ...countersign,
      };
      const report = verifyLedger([record]);
      expect(report.ok, JSON.stringify(countersign)).toBe(false);
      expect(report.issues.map((issue) => issue.kind)).toEqual(['host-signature-invalid']);
    }
  });

  it('decodes only unpadded base64url, as §5.1 pins it (RFC 4648 §5, RFC 7515 §2)', () => {
    expect(base64urlToBytes('ZmFrZQ')).toHaveLength(4);
    for (const malformed of ['Zm Fr ZQ', 'ZmFrZQ==', 'a+/b', 'ZmFr!ZQ', 'ZmFrZR']) {
      expect(base64urlToBytes(malformed), malformed).toBeUndefined();
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
      signer_seq: 0,
      signature: 'ZmFrZQ',
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
      host_signature: 'ZmFrZQ',
      host_key_id: HOST_KEY_ID,
      log_id: LOG_ID,
    };
    const report = verifyLedger([record]);
    expect(report.ok).toBe(false);
    expect(report.issues.some((issue) => issue.kind === 'schema-invalid')).toBe(true);
    expect(report.unchecked).toEqual(['countersignature']);
  });
});

describe('the stream-and-diffusion pass’s findings (§7.4, §11.3, §11.4)', () => {
  function l2Record(seq: number, signerSeq: number, previous: string, keyId = 'k1'): SealedRecord {
    const event = {
      ...makeAttempt(`00000000-0000-4000-8000-00000000000${seq + 1}`),
      key_id: keyId,
      signer_seq: signerSeq,
      signature: 'ZmFrZQ',
    };
    const hostTs = `2026-07-15T00:00:${String(seq + 2).padStart(2, '0')}.000Z`;
    return {
      event,
      seq,
      host_ts: hostTs,
      previous_hash: previous,
      record_hash: computeRecordHash(event, seq, hostTs, previous),
    };
  }

  it('refuses a Level-2 session that switches Polluted Stop off (§11.3)', () => {
    const endpoint = new CannedEndpoint(canned());
    const signer = { keyId: 'k1', sign: async (event: Record<string, unknown>) => event };
    expect(() => new AmcpSession(new InProcessTransport(endpoint), SESSION, { signer, pollutedStop: false })).toThrow(
      /Polluted Stop/,
    );
  });

  it('reports a run of missing signer_seq values in a session as one gap (§7.4, §11.4)', () => {
    const first = l2Record(0, 0, '0'.repeat(64));
    const report = verifyLedger([first, l2Record(1, 5, first.record_hash)]);
    const gaps = report.issues.filter((issue) => issue.kind === 'signer-seq-gap');
    expect(gaps).toHaveLength(1);
    expect(gaps[0]?.detail).toContain('signer_seq 1..4');
  });

  it('reports a session that does not start at zero (§7.4, §11.4)', () => {
    const report = verifyLedger([l2Record(0, 1, '0'.repeat(64))]);
    expect(report.issues.map((issue) => issue.kind)).toEqual(['signer-seq-gap']);
  });

  it('does not call contiguous signer_seqs a gap (§7.4)', () => {
    const first = l2Record(0, 0, '0'.repeat(64));
    const report = verifyLedger([first, l2Record(1, 1, first.record_hash)]);
    expect(report.issues.map((issue) => issue.kind)).not.toContain('signer-seq-gap');
  });

  it('performs Level-2 validation when given a checker (§11.4)', () => {
    const report = verifyLedger(
      [l2Record(0, 0, '0'.repeat(64))],
      undefined,
      undefined,
      undefined,
      undefined,
      () => false,
    );
    expect(report.ok).toBe(false);
    expect(report.issues.map((issue) => issue.kind)).toContain('signature-invalid');
    expect(report.unchecked).toEqual([]);
  });

  it('names the Level-2 records unchecked without one (§11.4)', () => {
    const report = verifyLedger([l2Record(0, 0, '0'.repeat(64))]);
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['level-2-signature']);
  });
});

describe('registry roles (§5.2, §10.9)', () => {
  it('one registry cannot serve both roles', () => {
    expect(() => new CountersignatureRegistryVerifier(new KeyRegistry(KeyRole.TOOL))).toThrow(/host-key registry/);
    expect(() => new KeyRegistryVerifier(new KeyRegistry(KeyRole.HOST))).toThrow(/tool-key registry/);
  });

  it('a tool cannot sign itself into the host-countersigned state', () => {
    const toolKey = generateToolKey('tool-k1');
    const shared = new KeyRegistry(KeyRole.TOOL);
    shared.registerToolKey(toolKey);
    // The misuse the guard forbids: the countersign verifier would resolve host_key_id "tool-k1".
    expect(() => new CountersignatureRegistryVerifier(shared)).toThrow();
    // A host-key registry the tool's key was never put into refuses it, as §5.2 requires.
    const verifier = new CountersignatureRegistryVerifier(new KeyRegistry(KeyRole.HOST));
    const payload = countersignaturePayload(0, '2026-07-15T00:00:02.000Z', LOG_ID, '0'.repeat(64), 'a'.repeat(64));
    const forged = Buffer.from(nobleEd25519Engine.sign(payload, toolKey.privateKey)).toString('base64');
    expect(verifier.check('tool-k1', forged, payload)).toBe(false);
  });
});
