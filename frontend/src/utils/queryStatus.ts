// Mirror of BLOCKED_STATUSES in backend/constants.py — keep the two in step. Pi-hole reports
// the specific GRAVITY/REGEX/... codes; AdGuard and Technitium are normalised to plain BLOCKED.
const BLOCKED_STATUSES: ReadonlySet<string> = new Set([
  'GRAVITY', 'GRAVITY_CNAME',
  'REGEX', 'REGEX_CNAME',
  'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST',
  'DENYLIST', 'DENYLIST_CNAME',
  'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA', 'EXTERNAL_BLOCKED_EDE15',
  'BLOCKED',
]);

export function isBlockedStatus(status: string | null): boolean {
  return status !== null && BLOCKED_STATUSES.has(status.toUpperCase());
}

export function queryRowClass(status: string | null): string {
  return isBlockedStatus(status)
    ? 'bg-red-50 dark:bg-red-900/30 hover:bg-red-100 dark:hover:bg-red-900/40'
    : 'hover:bg-gray-50 dark:hover:bg-gray-700';
}
