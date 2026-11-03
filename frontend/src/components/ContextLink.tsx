import { Link } from 'react-router-dom';

import { contextPath } from '../utils/queryContext';

export default function ContextLink({ queryId }: { queryId: number }) {
  return (
    <Link
      to={contextPath(queryId)}
      title="Context: this device's lookups around this query"
      aria-label="Show this device's lookups around this query"
      className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-800/60 transition-colors"
    >
      <svg aria-hidden="true" className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="9" strokeWidth={2} />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 7v5l3 2" />
      </svg>
    </Link>
  );
}
