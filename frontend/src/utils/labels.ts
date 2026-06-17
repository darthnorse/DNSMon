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
