export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1).fill(0);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

// Closest existing option worth suggesting for `input`, or null when the input is
// too short, an exact (case-insensitive) match, or not close enough to anything.
export function nearestSuggestion(input: string, options: string[]): string | null {
  const norm = input.trim().toLowerCase();
  if (norm.length < 4) return null;
  let best: string | null = null;
  let bestDist = Infinity;
  for (const opt of options) {
    if (opt.trim().toLowerCase() === norm) return null;
    const d = levenshtein(norm, opt.trim().toLowerCase());
    if (d < bestDist) {
      bestDist = d;
      best = opt;
    }
  }
  const threshold = Math.min(2, Math.floor(norm.length / 4));
  return best !== null && bestDist >= 1 && bestDist <= threshold ? best : null;
}
