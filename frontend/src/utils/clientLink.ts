export interface ClientLink {
  client: string | null;
  from: Date | null;
  to: Date | null;
  servers: string[];
}

export const MAX_CLIENT_LENGTH = 45;
const MAX_SERVER_NAME_LENGTH = 100;
// Matches the `servers` max_length on /api/queries; a longer list would be rejected with a 422.
const MAX_SERVERS_PARAM_LENGTH = 1000;

function parseServers(value: string | null): string[] {
  const names = (value ?? '').split(',').map(s => s.trim()).filter(s => s && s.length <= MAX_SERVER_NAME_LENGTH);
  return names.join(',').length <= MAX_SERVERS_PARAM_LENGTH ? names : [];
}

function parseDate(value: string | null): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Read `?client=<ip>&from=<iso>&to=<iso>&servers=<a,b>` deep-link params (used by external
 * dashboards such as netdash). `to` defaults to now when only `from` is given,
 * is clamped to now, and a range that isn't from < to is dropped entirely.
 */
export function parseClientLink(params: URLSearchParams): ClientLink {
  const rawClient = params.get('client')?.trim() ?? '';
  const client = rawClient && rawClient.length <= MAX_CLIENT_LENGTH ? rawClient : null;
  const servers = parseServers(params.get('servers'));

  const now = new Date();
  const from = parseDate(params.get('from'));
  let to = parseDate(params.get('to')) ?? (from ? now : null);
  if (to && to > now) to = now;

  if (!from || !to || from >= to) {
    return { client, from: null, to: null, servers };
  }
  return { client, from, to, servers };
}

export function buildClientLink(path: string, link: Partial<ClientLink>): string {
  const params = new URLSearchParams();
  if (link.client) params.set('client', link.client);
  if (link.from && link.to) {
    params.set('from', link.from.toISOString());
    params.set('to', link.to.toISOString());
  }
  if (link.servers && link.servers.length > 0) params.set('servers', link.servers.join(','));
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function toLocalDatetimeString(date: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
