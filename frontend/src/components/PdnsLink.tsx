import { Link } from 'react-router-dom';

import { pdnsPath } from '../utils/pdns';

export default function PdnsLink({ value }: { value: string }) {
  return (
    <Link to={pdnsPath(value)} className="font-mono break-all text-blue-600 dark:text-blue-400 hover:underline">
      {value}
    </Link>
  );
}
