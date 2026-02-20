import { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { APP_VERSION, GITHUB_REPO } from '../version';

function isNewerVersion(latest: string, current: string): boolean {
  const parse = (v: string) => v.split(/[.-]/).map(s => parseInt(s, 10) || 0);
  const [a1, a2 = 0, a3 = 0] = parse(latest);
  const [b1, b2 = 0, b3 = 0] = parse(current);
  if (a1 !== b1) return a1 > b1;
  if (a2 !== b2) return a2 > b2;
  return a3 > b3;
}

function shouldShowRelease(version: string, dismissedVersion: string | null): boolean {
  return isNewerVersion(version, APP_VERSION) && version !== dismissedVersion;
}

const CACHE_KEY = 'dnsmon_latest_release';
const DISMISSED_KEY = 'dnsmon_dismissed_version';
const CACHE_DURATION_MS = 60 * 60 * 1000;

interface CachedRelease {
  version: string;
  url: string;
  checkedAt: number;
}

export default function UpdateBanner() {
  const { user } = useAuth();
  const [release, setRelease] = useState<Pick<CachedRelease, 'version' | 'url'> | null>(null);

  useEffect(() => {
    if (!user?.is_admin || APP_VERSION === 'dev') return;

    const dismissedVersion = sessionStorage.getItem(DISMISSED_KEY);

    try {
      const cached = sessionStorage.getItem(CACHE_KEY);
      if (cached) {
        const data: CachedRelease = JSON.parse(cached);
        if (Date.now() - data.checkedAt < CACHE_DURATION_MS) {
          if (shouldShowRelease(data.version, dismissedVersion)) {
            setRelease({ version: data.version, url: data.url });
          }
          return;
        }
      }
    } catch { /* ignore corrupt cache */ }

    const checkRelease = async () => {
      try {
        const res = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases/latest`);
        if (!res.ok) return;
        const data = await res.json();
        if (!data?.tag_name || !data?.html_url) return;
        const version = data.tag_name.replace(/^v/, '');
        const url = data.html_url;
        sessionStorage.setItem(CACHE_KEY, JSON.stringify({ version, url, checkedAt: Date.now() }));
        if (shouldShowRelease(version, dismissedVersion)) {
          setRelease({ version, url });
        }
      } catch { /* network error, ignore */ }
    };
    checkRelease();
  }, [user?.is_admin]);

  if (!release) return null;

  return (
    <div className="bg-blue-600 text-white px-4 py-2 text-sm flex items-center justify-center gap-3">
      <span>
        DNSMon v{release.version} is available
        <span className="hidden sm:inline"> (you're running v{APP_VERSION})</span>
      </span>
      <a
        href={release.url}
        target="_blank"
        rel="noopener noreferrer"
        className="underline font-medium hover:text-blue-100"
      >
        View release
      </a>
      <button
        type="button"
        onClick={() => {
          sessionStorage.setItem(DISMISSED_KEY, release.version);
          setRelease(null);
        }}
        className="ml-1 hover:bg-blue-700 rounded p-0.5 leading-none"
        aria-label="Dismiss"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
}
