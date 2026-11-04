import type { GeoInfo } from '../types';

export function hasGeo(geo: GeoInfo | null | undefined): geo is GeoInfo {
  return !!geo && (geo.country !== null || geo.org !== null);
}
