export const pdnsPath = (q: string): string => `/pdns?q=${encodeURIComponent(q)}`;

/** Only tells the two lookup views apart; the API validates the value. Domain names never contain ':'. */
export const isIpAddress = (value: string): boolean =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':');
