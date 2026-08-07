interface Props {
  threatType: string | null;
}

const LABELS: Record<string, string> = {
  malware: 'Malware',
};

export default function ThreatBadge({ threatType }: Props) {
  if (!threatType) return null;
  const label = LABELS[threatType] ?? threatType;
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300"
      title={`Flagged by a threat feed as ${label}`}
    >
      <span aria-hidden="true">⚠</span>
      {label}
    </span>
  );
}
