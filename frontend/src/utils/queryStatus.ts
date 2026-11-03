export function isBlockedStatus(status: string | null): boolean {
  const upper = status?.toUpperCase() ?? '';
  return upper.includes('GRAVITY') || upper.includes('BLACKLIST');
}
