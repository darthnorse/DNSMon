export const formatDateOrNever = (value: string | null): string =>
  value ? new Date(value).toLocaleString() : 'Never';
