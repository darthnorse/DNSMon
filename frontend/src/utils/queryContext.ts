import type { ContextScope, Query, QueryContextParams } from '../types';
import { MAX_CLIENT_LENGTH } from './clientLink';

export const CONTEXT_WINDOWS = [1, 2, 5, 15] as const;
export const DEFAULT_CONTEXT_WINDOW = 5;

const MAX_DOMAIN_LENGTH = 255;
const HAS_ZONE = /(Z|[+-]\d{2}:?\d{2})$/i;

/**
 * An external link's `at`, as a UTC ISO string, or null. A time with no zone is UTC (as the
 * API documents), not browser-local; and an unencoded `+02:00` arrives as ` 02:00`, since
 * URLSearchParams decodes `+` to a space, so the sign is put back.
 */
function normalizeAt(raw: string): string | null {
  const restored = raw.replace(/ (\d{2}:?\d{2})$/, '+$1');
  const parsed = new Date(HAS_ZONE.test(restored) ? restored : `${restored}Z`);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function parseWindow(value: string | null): number {
  const n = Number(value);
  return (CONTEXT_WINDOWS as readonly number[]).includes(n) ? n : DEFAULT_CONTEXT_WINDOW;
}

function parseScope(value: string | null): ContextScope {
  return value === 'all' ? 'all' : 'device';
}

/**
 * Read `/context` params: `query=<id>` anchors on a stored query; otherwise
 * `client=<ip>&at=<iso>` (+ `domain`) — the form external dashboards (netdash) link with.
 * Returns null when neither form is complete.
 */
export function parseContextLink(params: URLSearchParams): QueryContextParams | null {
  const window = parseWindow(params.get('window'));
  const scope = parseScope(params.get('scope'));

  const rawId = params.get('query');
  if (rawId !== null && /^\d{1,18}$/.test(rawId)) {
    return { query_id: Number(rawId), window, scope };
  }

  const client = params.get('client')?.trim() ?? '';
  const at = normalizeAt(params.get('at')?.trim() ?? '');
  if (!client || client.length > MAX_CLIENT_LENGTH || !at) {
    return null;
  }
  const domain = params.get('domain')?.trim() ?? '';
  return {
    client_ip: client,
    at,
    ...(domain && domain.length <= MAX_DOMAIN_LENGTH ? { domain } : {}),
    window,
    scope,
  };
}

export function contextPath(queryId: number): string {
  return `/context?query=${queryId}`;
}

export interface ContextRow {
  query: Query;
  repeat: number;
}

function isRepeatOf(a: Query, b: Query): boolean {
  return a.domain === b.domain && a.query_type === b.query_type && a.client_ip === b.client_ip && a.status === b.status;
}

/**
 * Merge back-to-back identical lookups: same domain, record type, client and status, so a merge
 * never hides a second device or a block. Order is the point, so non-adjacent repeats stay.
 */
export function collapseRepeats(queries: Query[]): ContextRow[] {
  const rows: ContextRow[] = [];
  for (const query of queries) {
    const last = rows[rows.length - 1];
    if (last && isRepeatOf(last.query, query)) {
      last.repeat += 1;
    } else {
      rows.push({ query, repeat: 1 });
    }
  }
  return rows;
}

export function formatOffset(timestamp: string, center: string): string {
  const seconds = Math.round((new Date(timestamp).getTime() - new Date(center).getTime()) / 1000);
  if (seconds === 0) return '0:00';
  const abs = Math.abs(seconds);
  const minutes = Math.floor(abs / 60);
  const rest = String(abs % 60).padStart(2, '0');
  return `${seconds < 0 ? '−' : '+'}${minutes}:${rest}`;
}
