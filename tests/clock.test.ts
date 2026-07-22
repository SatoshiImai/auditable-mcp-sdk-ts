import { describe, expect, it } from 'vitest';
import { type Clock, nowIso, SystemClock } from '../src/clock';

const ISO_MILLIS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

describe('nowIso returns millisecond-precision, Z-terminated ISO-8601', () => {
  it('matches the spec date-time pattern', () => {
    expect(nowIso()).toMatch(ISO_MILLIS_Z);
  });
});

describe('SystemClock satisfies Clock', () => {
  it('now() returns an ISO-8601 string', () => {
    const clock: Clock = new SystemClock();
    expect(clock.now()).toMatch(ISO_MILLIS_Z);
  });
});
