/** Deterministic PRNG (mulberry32). Same seed => same sequence, on every platform. */
export interface Rng {
  next(): number;
  /** Integer in [min, max]. */
  int(min: number, max: number): number;
  /** Multiplies value by a factor in [1 - spread, 1 + spread], rounded. */
  jitter(value: number, spread: number): number;
  hex(len: number): string;
}

export function createRng(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int(min, max) {
      return min + Math.floor(next() * (max - min + 1));
    },
    jitter(value, spread) {
      return Math.round(value * (1 - spread + next() * 2 * spread));
    },
    hex(len) {
      let s = '';
      for (let i = 0; i < len; i++) s += Math.floor(next() * 16).toString(16);
      return s;
    },
  };
}
