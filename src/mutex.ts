/**
 * A FIFO async mutex.
 *
 * §7.1 requires a host to assign `seq` and `previous_hash`, seal, and commit atomically with respect
 * to every other record being sealed into the same partition. Signing and persistence sit between
 * those steps, so the section spans awaits and needs mutual exclusion; the Python port uses
 * `anyio.Lock` for the same reason. Callers enter in call order, and a section that throws releases
 * the lock like any other.
 *
 * Internal: the public surface of the two ports stays name-for-name, and this is the one primitive
 * Python gets from its runtime rather than from this SDK.
 */
export class Mutex {
  #tail: Promise<unknown> = Promise.resolve();

  /** Run `section` once every earlier caller has finished, and return what it returns. */
  async run<T>(section: () => Promise<T>): Promise<T> {
    const earlier = this.#tail;
    let release!: () => void;
    // Claimed synchronously, before the first await, so call order is acquisition order.
    this.#tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await earlier.catch(() => undefined);
    try {
      return await section();
    } finally {
      release();
    }
  }
}
