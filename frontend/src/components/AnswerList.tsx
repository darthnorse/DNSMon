import { Link } from 'react-router-dom';

import { pdnsPath } from '../utils/pdns';

const LINK_CLASS = 'font-mono break-all text-blue-600 dark:text-blue-400 hover:underline';

function AnswerLinks({ values }: { values: string[] }) {
  return (
    <>
      {values.map((value) => (
        <Link key={value} to={pdnsPath(value)} className={LINK_CLASS}>{value}</Link>
      ))}
    </>
  );
}

/** NULL means the server doesn't report answers (Pi-hole); an empty list means it answered with nothing. */
export default function AnswerList({ ips, cnames, compact = false }: {
  ips: string[] | null;
  cnames: string[] | null;
  compact?: boolean;
}) {
  const unavailable = ips === null && cnames === null;
  // A Context table from a Pi-hole would repeat "not available" on every row without telling the reader anything.
  if (unavailable && compact) return null;
  if (unavailable) return <span className="text-sm text-gray-500 dark:text-gray-400">Answer not available from this server</span>;

  const ipList = ips ?? [];
  const cnameList = cnames ?? [];
  if (ipList.length === 0 && cnameList.length === 0) {
    return <span className={`${compact ? 'text-xs' : 'text-sm'} text-gray-500 dark:text-gray-400`}>No answer</span>;
  }

  if (compact) {
    return (
      <span className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs">
        <AnswerLinks values={cnameList} />
        <AnswerLinks values={ipList} />
      </span>
    );
  }

  return (
    <dl className="space-y-1 text-sm">
      {cnameList.length > 0 && (
        <div className="flex flex-wrap gap-x-3">
          <dt className="w-16 text-gray-500 dark:text-gray-400">CNAMEs</dt>
          <dd className="flex flex-wrap gap-x-3 min-w-0"><AnswerLinks values={cnameList} /></dd>
        </div>
      )}
      {ipList.length > 0 && (
        <div className="flex flex-wrap gap-x-3">
          <dt className="w-16 text-gray-500 dark:text-gray-400">IPs</dt>
          <dd className="flex flex-wrap gap-x-3 min-w-0"><AnswerLinks values={ipList} /></dd>
        </div>
      )}
    </dl>
  );
}
