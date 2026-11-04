import type { GeoInfo } from '../types';
import { hasGeo } from '../utils/geo';

export default function GeoLabel({ geo }: { geo: GeoInfo | null | undefined }) {
  if (!hasGeo(geo)) return null;
  const place = [geo.city, geo.country_name ?? geo.country].filter(Boolean).join(', ');
  const title = [place, geo.asn !== null ? `AS${geo.asn}` : null].filter(Boolean).join(' · ');
  return (
    <span className="text-gray-500 dark:text-gray-400" title={title || undefined}>
      {[geo.country, geo.org].filter(Boolean).join(' · ')}
    </span>
  );
}
