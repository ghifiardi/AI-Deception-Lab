/**
 * Statistics for deception experiments. Deterministic (seeded bootstrap).
 *
 *   wilson(k, n)                    95% Wilson score interval for a proportion
 *   newcombe(k1, n1, k2, n2)        95% interval for p1 - p2 (Newcombe hybrid score, method 10)
 *   bootstrapMedian(xs, seed)       95% percentile bootstrap interval for a median
 *   bootstrapMedianDiff(a, b, seed) 95% percentile bootstrap interval for median(a) - median(b)
 *
 * Evidence status of a comparison:
 *   'validated'   only if ALL hold: the configuration was pre-registered and matched,
 *                 n >= MIN_N_VALIDATED in both arms, the 95% interval excludes 0,
 *                 every run log verified, and invalid runs <= 10% per arm.
 *   'exploratory' otherwise (the reasons are listed). Exploratory findings are
 *                 hypotheses for a future pre-registered run, not conclusions.
 */
export const Z95 = 1.959963984540054;
export const MIN_N_VALIDATED = 20;
export const BOOTSTRAP_B = 2000;

export function wilson(k, n, z = Z95) {
  if (!n) return { estimate: null, lo: null, hi: null, k, n };
  const p = k / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { estimate: p, lo: Math.max(0, centre - half), hi: Math.min(1, centre + half), k, n };
}

/** Newcombe (1998) hybrid score interval for a difference of independent proportions. */
export function newcombe(k1, n1, k2, n2, z = Z95) {
  if (!n1 || !n2) return { estimate: null, lo: null, hi: null };
  const a = wilson(k1, n1, z);
  const b = wilson(k2, n2, z);
  const d = a.estimate - b.estimate;
  const lo = d - Math.sqrt((a.estimate - a.lo) ** 2 + (b.hi - b.estimate) ** 2);
  const hi = d + Math.sqrt((a.hi - a.estimate) ** 2 + (b.estimate - b.lo) ** 2);
  return { estimate: d, lo: Math.max(-1, lo), hi: Math.min(1, hi) };
}

export function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((x, y) => x - y);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function percentile(sorted, q) {
  const i = (sorted.length - 1) * q;
  const lo = Math.floor(i);
  const hi = Math.ceil(i);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
}

const resample = (xs, r) => xs.map(() => xs[Math.floor(r() * xs.length)]);

export function bootstrapMedian(xs, seed = 1, B = BOOTSTRAP_B) {
  if (!xs.length) return { estimate: null, lo: null, hi: null, n: 0 };
  const r = rng(seed);
  const meds = Array.from({ length: B }, () => median(resample(xs, r))).sort((x, y) => x - y);
  return { estimate: median(xs), lo: percentile(meds, 0.025), hi: percentile(meds, 0.975), n: xs.length };
}

export function bootstrapMedianDiff(a, b, seed = 1, B = BOOTSTRAP_B) {
  if (!a.length || !b.length) return { estimate: null, lo: null, hi: null };
  const r = rng(seed);
  const diffs = Array.from({ length: B }, () => median(resample(a, r)) - median(resample(b, r))).sort((x, y) => x - y);
  return { estimate: median(a) - median(b), lo: percentile(diffs, 0.025), hi: percentile(diffs, 0.975) };
}

/**
 * Decide evidence status for one comparison.
 * @param {{ ci: { lo: number|null, hi: number|null }, nA: number, nB: number, invalidA: number, invalidB: number,
 *           preregistered: boolean, logsVerified: boolean }} c
 */
/** @param {{ ci: { lo: number | null, hi: number | null }, nA: number, nB: number, invalidA: number, invalidB: number, preregistered: boolean, hypothesis?: string | null, logsVerified: boolean }} c */
export function evidenceStatus(c) {
  const reasons = [];
  if (!c.preregistered) reasons.push('not pre-registered');
  else if (c.hypothesis === null) reasons.push('not a pre-registered hypothesis (post hoc)');
  if (c.nA < MIN_N_VALIDATED || c.nB < MIN_N_VALIDATED) reasons.push(`n < ${MIN_N_VALIDATED} per arm (${c.nA} vs ${c.nB})`);
  if (c.ci.lo === null || c.ci.hi === null) reasons.push('interval not computable');
  else if (c.ci.lo <= 0 && c.ci.hi >= 0) reasons.push('95% interval includes 0');
  if (!c.logsVerified) reasons.push('run logs failed verification');
  const invalidShare = (inv, n) => (n + inv ? inv / (n + inv) : 0);
  if (invalidShare(c.invalidA, c.nA) > 0.1 || invalidShare(c.invalidB, c.nB) > 0.1) reasons.push('more than 10% invalid runs');
  return { status: reasons.length ? 'exploratory' : 'validated', reasons };
}

/**
 * Find the pre-registered hypothesis for one comparison and judge it against
 * the registered direction. Returns { hypothesis, verdict } where verdict is
 * 'supported' | 'contradicted' | 'inconclusive', or null when unregistered.
 */
/** @param {string} comparison @param {string} metric @param {{ lo: number | null, hi: number | null }} ci @param {Array<{ id: string, comparison: string, metric: string, direction: string }>} [hypotheses] */
export function hypothesisVerdict(comparison, metric, ci, hypotheses = []) {
  const h = hypotheses.find((x) => x.comparison === comparison && x.metric === metric);
  if (!h) return { hypothesis: null, verdict: null };
  let verdict = 'inconclusive';
  if (ci.lo !== null && ci.hi !== null) {
    if (ci.hi < 0) verdict = h.direction === 'negative' ? 'supported' : 'contradicted';
    else if (ci.lo > 0) verdict = h.direction === 'positive' ? 'supported' : 'contradicted';
  }
  return { hypothesis: h.id, verdict };
}
