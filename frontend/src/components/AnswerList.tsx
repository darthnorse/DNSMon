import GeoLabel from './GeoLabel';
import PdnsLink from './PdnsLink';
import { hasGeo } from '../utils/geo';
import type { GeoInfo } from '../types';

function AnswerLinks({ values, geo }: { values: string[]; geo?: Record<string, GeoInfo> | null }) {
  return (
    <>
      {values.map((value) => {
        const info = geo?.[value];
        if (!hasGeo(info)) return <PdnsLink key={value} value={value} />;
        return (
          <span key={value} className="inline-flex flex-wrap items-baseline gap-x-2">
            <PdnsLink value={value} />
            <GeoLabel geo={info} />
          </span>
        );
      })}
    </>
  );
}

/** NULL means the server doesn't report answers (Pi-hole); an empty list means it answered with nothing. */
export default function AnswerList({ ips, cnames, geo, compact = false }: {
  ips: string[] | null;
  cnames: string[] | null;
  geo?: Record<string, GeoInfo> | null;
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
        <AnswerLinks values={ipList} geo={geo} />
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
          <dd className="flex flex-wrap gap-x-3 min-w-0"><AnswerLinks values={ipList} geo={geo} /></dd>
        </div>
      )}
    </dl>
  );
}
