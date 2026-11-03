const STORAGE_KEY = 'dnsmon.postLoginPath';
const MAX_AGE_MS = 10 * 60 * 1000;

interface ParkedPath {
  path: string;
  savedAt: number;
}

function isSafeAppPath(path: string): boolean {
  return path.startsWith('/') && !path.startsWith('//') && !path.startsWith('/\\');
}

/** The OIDC round-trip always lands on `/`, so the deep link being opened is parked here.
 *  Saving `/` clears any older entry, so an abandoned attempt can't hijack a later login. */
export function savePostLoginPath(path: string): void {
  try {
    if (!isSafeAppPath(path) || path === '/') {
      sessionStorage.removeItem(STORAGE_KEY);
      return;
    }
    const parked: ParkedPath = { path, savedAt: Date.now() };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(parked));
  } catch {
    // Storage unavailable (private mode, blocked site data): the user lands on `/` instead.
  }
}

export function takePostLoginPath(): string | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
    if (!raw) return null;
    const parked = JSON.parse(raw) as Partial<ParkedPath>;
    if (typeof parked.path !== 'string' || typeof parked.savedAt !== 'number') return null;
    if (Date.now() - parked.savedAt > MAX_AGE_MS) return null;
    return isSafeAppPath(parked.path) ? parked.path : null;
  } catch {
    return null;
  }
}
