import type { PiholeServer } from '../types';

export const SERVER_SORT_OPTIONS = [
  { value: 'added', label: 'Added order' },
  { value: 'name', label: 'Name' },
  { value: 'address', label: 'Address' },
] as const;

export type ServerSort = typeof SERVER_SORT_OPTIONS[number]['value'];

export const DEFAULT_SERVER_SORT: ServerSort = 'added';

const STORAGE_KEY = 'settings_serverSort';
const IP_HOST = /^(\[.*\]|\d+\.\d+\.\d+\.\d+)$/;
// Numeric collation puts adguard2 before adguard10 and 192.168.1.9 before 192.168.1.11.
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

export function loadServerSort(): ServerSort {
  const stored = localStorage.getItem(STORAGE_KEY);
  return SERVER_SORT_OPTIONS.find((option) => option.value === stored)?.value ?? DEFAULT_SERVER_SORT;
}

export function saveServerSort(sort: ServerSort): void {
  localStorage.setItem(STORAGE_KEY, sort);
}

function parseAddress(url: string): { host: string; port: number } {
  try {
    const parsed = new URL(url);
    return { host: parsed.hostname, port: Number(parsed.port) };
  } catch {
    return { host: url, port: 0 };
  }
}

function compareAddress(a: string, b: string): number {
  const left = parseAddress(a);
  const right = parseAddress(b);
  return Number(!IP_HOST.test(left.host)) - Number(!IP_HOST.test(right.host))
    || collator.compare(left.host, right.host)
    || left.port - right.port;
}

export function sortServers(servers: PiholeServer[], sort: ServerSort): PiholeServer[] {
  if (sort === 'name') {
    return [...servers].sort((a, b) => collator.compare(a.name, b.name));
  }
  if (sort === 'address') {
    return [...servers].sort((a, b) => compareAddress(a.url, b.url));
  }
  return servers;
}
