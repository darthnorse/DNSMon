const LABEL_SEPARATOR = ' · ';

/**
 * Render a domain's classification as a single inline string.
 * - app + category  -> "Instagram · Social"
 * - category only   -> "Advertising"
 * - app only        -> "Instagram"
 * - neither         -> "" (caller renders nothing)
 */
export function formatDomainLabel(
  appName: string | null,
  category: string | null,
): string {
  if (appName && category) {
    return `${appName}${LABEL_SEPARATOR}${category}`;
  }
  return appName || category || '';
}

/**
 * Human-readable label for an app-definition `source` / `matched_source` value.
 * Falls back to the raw value for anything unmapped (e.g. a future source).
 */
export function sourceLabel(source: string | null): string {
  if (!source) return '';
  const labels: Record<string, string> = {
    adguard: 'AdGuard',
    dnsmon: 'DNSMon',
    v2fly: 'v2fly Community',
    manual: 'Manual',
    blocklist: 'Blocklist',
  };
  return labels[source] ?? source;
}
