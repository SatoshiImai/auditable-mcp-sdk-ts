import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { type AttemptResponse, Countersign, Level, SPEC_VERSION } from '../src/models';
import { AmcpAbortedError, AmcpSession } from '../src/session';
import { AmcpUsageError, type AuditTransport, accept, reject } from '../src/transport';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { FixedDeps, L2_CAPABILITY, MonotonicClock, OkVerifier, SESSION, StubEndpoint, StubSigner } from './helpers';

const TABLE = { kind: 'table', ref: 'orders' };

function l1Pair(): { host: AuditHost; session: AmcpSession } {
  const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
  host.openSession(SESSION);
  const session = new AmcpSession(new InProcessTransport(host), SESSION, { deps: new FixedDeps() });
  return { host, session };
}

function lastOutcome(host: AuditHost): unknown {
  const records = host.records();
  return records[records.length - 1]?.event.outcome;
}

describe('withAudit maps the handler result to the terminal outcome', () => {
  it('seals attempt + success and returns the handler value', async () => {
    const { host, session } = l1Pair();
    const result = await withAudit(
      session,
      { actionType: 'db.query', targetResource: TABLE, mutates: false, egress: true },
      () => 42,
    );
    expect(result).toBe(42);
    expect(host.records()).toHaveLength(2);
    expect(lastOutcome(host)).toBe('success');
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });

  it('seals a failed outcome and rethrows when the handler throws', async () => {
    const { host, session } = l1Pair();
    await expect(
      withAudit(session, { actionType: 'db.write', targetResource: TABLE, mutates: true, egress: false }, () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(host.records()).toHaveLength(2);
    expect(lastOutcome(host)).toBe('failed');
  });

  it('throws AmcpAbortedError and does not run the handler when the host refuses', async () => {
    // An L2 host with an unsigned session: the attempt is rejected as l2-unsigned.
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, { deps: new FixedDeps() });
    let ran = false;
    await expect(
      withAudit(session, { actionType: 'db.write', targetResource: TABLE, mutates: true, egress: false }, () => {
        ran = true;
      }),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(ran).toBe(false);
    expect(host.records()).toHaveLength(0);
  });
});

describe('await using is the fail-closed primitive', () => {
  it('records success only when succeeded() is called', async () => {
    const { host, session } = l1Pair();
    await (async () => {
      await using action = await session.action('db.query', TABLE, { mutates: false, egress: true });
      expect(action.accept?.seq).toBe(0);
      action.succeeded();
    })();
    expect(lastOutcome(host)).toBe('success');
  });

  it('seals one terminal outcome however often the action is disposed (§8.3)', async () => {
    // `await using` disposes once, but the disposer is a public method and a caller may also invoke
    // it. A second terminal outcome for an id the host sealed once is a duplicate record, not a fact.
    const { host, session } = l1Pair();
    const action = await session.action('db.query', TABLE, { mutates: false, egress: true });
    action.succeeded();
    await action[Symbol.asyncDispose]();
    await action[Symbol.asyncDispose]();
    expect(host.records().filter((record) => record.event.outcome !== 'attempted')).toHaveLength(1);
  });

  it('fails closed to failed when succeeded() is forgotten', async () => {
    const { host, session } = l1Pair();
    await (async () => {
      await using _action = await session.action('db.query', TABLE, { mutates: false, egress: true });
      // deliberately do not call succeeded()
    })();
    expect(lastOutcome(host)).toBe('failed');
  });

  it('fails closed to failed and does not suppress an exception in the block', async () => {
    const { host, session } = l1Pair();
    await expect(
      (async () => {
        await using _action = await session.action('db.write', TABLE, { mutates: true, egress: false });
        throw new Error('boom');
      })(),
    ).rejects.toThrow('boom');
    expect(lastOutcome(host)).toBe('failed');
  });
});

describe('Polluted Stop (§7.2)', () => {
  it('aborts with hash-mismatch when the accept record_hash is tampered', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const tampering: AuditTransport = {
      negotiate: (offered) => new InProcessTransport(host).negotiate(offered),
      sendAttempt: async (event) => {
        const response = await host.handleAttempt(event);
        return response.status === 'accept' ? { ...response, record_hash: 'f'.repeat(64) } : response;
      },
      sendOutcome: (event) => host.handleOutcome(event),
    };
    // pollutedStop opted in under L1 to exercise the check without a signer.
    const session = new AmcpSession(tampering, SESSION, { deps: new FixedDeps(), pollutedStop: true });

    let error: unknown;
    try {
      await withAudit(session, { actionType: 'db.write', targetResource: TABLE, mutates: true, egress: false }, () => {
        throw new Error('handler should not run');
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(AmcpAbortedError);
    expect((error as AmcpAbortedError).reason).toBe('hash-mismatch');
  });
});

describe('Level 2 session end-to-end', () => {
  it('signs, passes Polluted Stop, and seals a verifiable chain', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, {
      deps: new FixedDeps(),
      signer: new StubSigner(),
    });
    const result = await withAudit(
      session,
      {
        actionType: 'db.query',
        targetResource: TABLE,
        mutates: false,
        egress: true,
        disclose: { dialect: 'postgres' },
      },
      () => 'ok',
    );
    expect(result).toBe('ok');
    expect(host.records()).toHaveLength(2);
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });
});

/** A transport whose send throws, as a wire transport can (§11.3). */
class FaultyTransport implements AuditTransport {
  readonly outcomes: Record<string, unknown>[] = [];
  readonly #outcomeAlsoFails: boolean;

  constructor(outcomeAlsoFails = false) {
    this.#outcomeAlsoFails = outcomeAlsoFails;
  }

  negotiate(): never {
    throw new Error('not used by these tests');
  }

  async sendAttempt(): Promise<never> {
    throw new Error('the wire went away');
  }

  async sendOutcome(event: Record<string, unknown>): Promise<void> {
    if (this.#outcomeAlsoFails) {
      throw new Error('the wire is still gone');
    }
    this.outcomes.push(event);
  }
}

describe('a transport fault (§6, §11.3)', () => {
  const spec = {
    actionType: 'db.read',
    target: { kind: 'table', ref: 'customers' },
    mutates: false,
    egress: false,
  } as const;

  it('aborts rather than escaping as the transport’s own error', async () => {
    const session = new AmcpSession(new FaultyTransport(), SESSION, { deps: new FixedDeps() });
    await expect(
      (async () => {
        await using action = await session.action(spec.actionType, spec.target, spec);
        action.succeeded();
      })(),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
  });

  it('carries the transport fault as the abort’s cause', async () => {
    // The abort says the action did not happen; the cause says why. Dropping it leaves an operator
    // with a `host-unavailable` and no way to tell a dead socket from a refusing host.
    const session = new AmcpSession(new FaultyTransport(), SESSION, { deps: new FixedDeps() });
    const aborted = await (async () => {
      try {
        await using action = await session.action(spec.actionType, spec.target, spec);
        action.succeeded();
        return undefined;
      } catch (error) {
        return error;
      }
    })();
    expect(aborted).toBeInstanceOf(AmcpAbortedError);
    expect((aborted as AmcpAbortedError).cause).toBeInstanceOf(Error);
    expect(String((aborted as AmcpAbortedError).cause)).toContain('the wire went away');
  });

  it('leaves an aborted record of the action that did not happen', async () => {
    const transport = new FaultyTransport();
    const session = new AmcpSession(transport, SESSION, { deps: new FixedDeps() });
    await expect(
      (async () => {
        await using _action = await session.action(spec.actionType, spec.target, spec);
      })(),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(transport.outcomes.map((event) => event.outcome)).toEqual(['aborted']);
    expect(transport.outcomes[0]?.reason).toBe('host-unavailable');
  });

  it('a transport that fails twice does not mask the abort', async () => {
    const session = new AmcpSession(new FaultyTransport(true), SESSION, { deps: new FixedDeps() });
    await expect(
      (async () => {
        await using _action = await session.action(spec.actionType, spec.target, spec);
      })(),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
  });
});

/** A transport that refuses because the SDK's own contract was broken, not because the wire is. */
class MisusedTransport extends FaultyTransport {
  override async sendAttempt(): Promise<never> {
    throw new AmcpUsageError('this session is not audit-negotiated');
  }
}

describe('misuse is not a transport fault (§6.2, §11.3)', () => {
  it('reaches the caller instead of becoming host-unavailable', async () => {
    const transport = new MisusedTransport();
    const session = new AmcpSession(transport, SESSION, { deps: new FixedDeps() });
    await expect(
      (async () => {
        await using _action = await session.action(
          'db.read',
          { kind: 'table', ref: 'customers' },
          { mutates: false, egress: false },
        );
      })(),
    ).rejects.toBeInstanceOf(AmcpUsageError);
    // Blaming the host for the integrator's wiring buries the one thing they need to see.
    expect(transport.outcomes).toHaveLength(0);
  });
});

/** The tool's own signer is down. The host is fine. */
class DeadSigner {
  readonly keyId = 'k1';
  async sign(): Promise<never> {
    throw new Error('KMS unreachable');
  }
}

/** A host that rejects every attempt and then fails while recording the abort. */
class RefusingHost extends StubEndpoint {
  readonly capability = {
    spec_version: SPEC_VERSION,
    level: Level.L1,
    attempt: 'request',
    countersign: Countersign.NONE,
  } as const;
  outcomes = 0;
  async handleAttempt(): Promise<AttemptResponse> {
    return reject('schema-invalid');
  }
  async handleOutcome(): Promise<void> {
    this.outcomes += 1;
    throw new Error('the wire went away mid-abort');
  }
}

describe('a tool-side failure is not the host’s failure (§7.2, §7.6)', () => {
  const spec = { target: { kind: 'table', ref: 'customers' }, mutates: false, egress: false } as const;

  it('a dead signer reaches the caller as itself', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, {
      signer: new DeadSigner(),
      deps: new FixedDeps(),
    });
    await expect(
      (async () => {
        await using _action = await session.action('db.read', spec.target, spec);
      })(),
    ).rejects.toThrow('KMS unreachable');
    // host-unavailable would send an operator to a host that is answering perfectly well.
    expect(host.records()).toHaveLength(0);
  });

  it('a failure to record the abort does not replace the abort', async () => {
    const endpoint = new RefusingHost();
    const session = new AmcpSession(new InProcessTransport(endpoint), SESSION, { deps: new FixedDeps() });
    await expect(
      (async () => {
        await using _action = await session.action('db.read', spec.target, spec);
      })(),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(endpoint.outcomes).toBe(1);
  });
});

/** Accepts the attempt, then the wire dies before the outcome can be sent. */
class AcceptsThenDies extends StubEndpoint {
  readonly capability = {
    spec_version: SPEC_VERSION,
    level: Level.L1,
    attempt: 'request',
    countersign: Countersign.NONE,
  } as const;
  async handleAttempt(): Promise<AttemptResponse> {
    return accept(0, '0'.repeat(64), '2026-07-15T00:00:01.000Z', '0'.repeat(64));
  }
  async handleOutcome(): Promise<void> {
    throw new Error('the wire went away');
  }
}

describe('the terminal outcome never replaces the body’s error (§6, §10.8)', () => {
  const spec = { target: { kind: 'table', ref: 'customers' }, mutates: false, egress: false } as const;

  it('the body’s error reaches the caller', async () => {
    const session = new AmcpSession(new InProcessTransport(new AcceptsThenDies()), SESSION, {
      deps: new FixedDeps(),
    });
    // A throwing disposer would reach the caller as a SuppressedError wrapping this one.
    await expect(
      (async () => {
        await using _action = await session.action('db.read', spec.target, spec);
        throw new Error('the real problem');
      })(),
    ).rejects.toThrow('the real problem');
  });

  it('a successful body does not fail on a lost outcome', async () => {
    const session = new AmcpSession(new InProcessTransport(new AcceptsThenDies()), SESSION, {
      deps: new FixedDeps(),
    });
    await (async () => {
      await using action = await session.action('db.read', spec.target, spec);
      action.succeeded();
    })();
  });
});

describe('the session id is checked where it is chosen (§6.3)', () => {
  it.each([
    'call-1',
    SESSION.toUpperCase(),
    '00000000-0000-0000-0000-000000000000',
  ])('refuses %s at construction, naming the rule', (sessionId) => {
    const transport = new InProcessTransport(new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() }));
    expect(() => new AmcpSession(transport, sessionId)).toThrow(AmcpUsageError);
    expect(() => new AmcpSession(transport, sessionId)).toThrow(/lowercase RFC 9562 UUID/);
  });
});
