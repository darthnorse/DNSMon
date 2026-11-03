import { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { buildClientLink } from '../utils/clientLink';

export function clientDetailPath(clientIp: string): string {
  return buildClientLink('/statistics', { client: clientIp });
}

export default function ClientDetailLink({ clientIp, className = '', children }: { clientIp: string; className?: string; children: ReactNode }) {
  return (
    <Link
      to={clientDetailPath(clientIp)}
      title={`View DNS activity for ${clientIp}`}
      className={`hover:underline hover:text-blue-600 dark:hover:text-blue-400 ${className}`}
    >
      {children}
    </Link>
  );
}
