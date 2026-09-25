/** Round tokens name their instance, and the affinity header mirrors the session (§6.4, round affinity). */

import { InMemoryTransport } from '@modelcontextprotocol/client';
import { describe, expect, it } from 'vitest';
import {
  AFFINITY_HEADER,
  instanceOfToken,
  isInstanceId,
  McpAuditTransport,
  McpBindingError,
  mintRoundToken,
  newInstanceId,
  PROCESS_INSTANCE,
  ROUND_TOKEN_PREFIX,
} from '../src/mcp';
import { withAffinityHeader } from '../src/mcp/affinity';
import { type AuditCapability, Countersign, Level, SPEC_VERSION } from '../src/models';

const CAP: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};

describe('round tokens', () => {
  it('carry the instance, and 43 characters of base64url drawn from 32 random bytes', () => {
    const token = mintRoundToken('instance-a');
    expect(token).toMatch(/^amcp\.instance-a\.[A-Za-z0-9_-]{43}$/);
    expect(instanceOfToken(token)).toBe('instance-a');
    expect(mintRoundToken('instance-a')).not.toBe(token);
  });

  it('name no instance when they are not of that form', () => {
    for (const value of [
      'amcp.',
      'amcp.instance-a',
      `amcp..${'A'.repeat(43)}`,
      `amcp.instance-a.${'A'.repeat(42)}`,
      `amcp.a/b.${'A'.repeat(43)}`,
      `amcp.${'a'.repeat(65)}.${'A'.repeat(43)}`,
      `other.instance-a.${'A'.repeat(43)}`,
    ]) {
      expect(instanceOfToken(value)).toBeUndefined();
    }
  });

  it('default to an instance drawn at random, which is a valid instance name', () => {
    expect(isInstanceId(PROCESS_INSTANCE)).toBe(true);
    expect(PROCESS_INSTANCE).toHaveLength(22);
    expect(newInstanceId()).not.toBe(PROCESS_INSTANCE);
  });

  it('are refused an instance name outside [A-Za-z0-9_-]{1,64}', () => {
    const [, wire] = InMemoryTransport.createLinkedPair();
    expect(() => new McpAuditTransport(wire, CAP, { instance: 'a.b' })).toThrow(McpBindingError);
    expect(new McpAuditTransport(wire, CAP, { instance: 'a_b-1' }).instance).toBe('a_b-1');
    expect(new McpAuditTransport(wire, CAP).instance).toBe(PROCESS_INSTANCE);
  });

  it('refuse to pass a JSON-RPC batch through the seam, which would carry its members past it unaudited', async () => {
    const [, wire] = InMemoryTransport.createLinkedPair();
    const seam = new McpAuditTransport(wire, CAP);
    const batch: unknown = [{ jsonrpc: '2.0', id: 1, result: {} }];
    const send: (message: unknown) => Promise<void> = (message) => Reflect.apply(seam.send, seam, [message]);
    await expect(send(batch)).rejects.toThrow(McpBindingError);
  });

  it('keep the reserved prefix', () => {
    expect(mintRoundToken('x').startsWith(ROUND_TOKEN_PREFIX)).toBe(true);
  });
});

describe('the affinity header', () => {
  it('is set once whatever spelling the headers already had, and the other headers stay', () => {
    const headers = withAffinityHeader({ 'auditable-mcp-session': 'stale', 'Mcp-Param-Region': 'eu' }, 'fresh');
    expect(headers).toEqual({ 'Mcp-Param-Region': 'eu', [AFFINITY_HEADER]: 'fresh' });
    expect(withAffinityHeader(undefined, 's')).toEqual({ [AFFINITY_HEADER]: 's' });
  });
});
