import { isBlockedStatus } from '../utils/queryStatus';

export default function StatusBadge({ status, className = '' }: { status: string | null; className?: string }) {
  const tone = isBlockedStatus(status)
    ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
    : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200';
  return (
    <span className={`px-2 py-1 rounded-full text-xs whitespace-nowrap ${tone} ${className}`}>
      {status || 'unknown'}
    </span>
  );
}
