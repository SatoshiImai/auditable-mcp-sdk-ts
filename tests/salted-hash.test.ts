import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { disclosureOf, newSalt, openSaltedHash, SALTED_HASH_PATTERN, saltedHashOf } from '../src/salted-hash';
import { AmcpSession } from '../src/session';
import { FixedDeps, MonotonicClock, SESSION } from './helpers';
import { saltedHashVectors } from './vectors';

describe('the salted hash reproduces the shared vectors (§4.3)', () => {
  for (const vector of saltedHashVectors) {
    it(vector.name, () => {
      expect(saltedHashOf(vector.disclosure)).toBe(vector.salted_hash);
      const [salt, value] = vector.decoded;
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        expect(disclosureOf(salt, value as Record<string, unknown>)).toBe(vector.disclosure);
        expect(openSaltedHash(vector.disclosure, vector.salted_hash)).toEqual(value);
      }
    });
  }
});

describe('opening a salted hash', () => {
  it('opens with its own Disclosure and with no other', () => {
    const context = { table: 'customers', rows: 3 };
    const disclosure = disclosureOf(newSalt(), context);
    const hash = saltedHashOf(disclosure);
    expect(hash).toMatch(new RegExp(SALTED_HASH_PATTERN));
    expect(openSaltedHash(disclosure, hash)).toEqual(context);
    expect(openSaltedHash(disclosureOf(newSalt(), context), hash)).toBeUndefined();
  });

  it('refuses a Disclosure that is not a salt and an object', () => {
    for (const decoded of [['s'], ['s', 'US'], [1, {}], ['s', {}, 'x']]) {
      const disclosure = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
      expect(openSaltedHash(disclosure, saltedHashOf(disclosure))).toBeUndefined();
    }
  });
});

describe('an action given commitSalted', () => {
  it('seals one salted hash on its attempt and its outcome, opened by the Disclosure it exposes', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, { deps: new FixedDeps() });
    const context = { customer: '山田太郎', amount: 1200000 };
    let disclosure: string | undefined;
    await (async () => {
      await using action = await session.action(
        'payment.send',
        { kind: 'account', ref: 'acct-1' },
        { mutates: true, egress: true, commitSalted: context },
      );
      disclosure = action.disclosure;
      action.succeeded();
    })();
    const hashes = host.records().map((record) => record.event.action_context_salted_hash);
    expect(hashes).toHaveLength(2);
    expect(hashes[0]).toBe(hashes[1]);
    expect(disclosure).toBeDefined();
    expect(openSaltedHash(disclosure as string, hashes[0] as string)).toEqual(context);
    expect(JSON.stringify(host.records())).not.toContain('山田太郎');
  });
});
