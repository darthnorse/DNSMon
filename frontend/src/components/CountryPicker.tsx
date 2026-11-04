import { useEffect, useState } from 'react';
import type { GeoipCountry } from '../types';

interface CountryPickerProps {
  id: string;
  label: string;
  value: string;
  countries: GeoipCountry[];
  onChange: (value: string) => void;
  onUnresolvedChange: (unresolved: boolean) => void;
}

const toCodes = (value: string): string[] =>
  value.split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);

const optionLabel = (c: GeoipCountry): string => `${c.name} (${c.code})`;

export default function CountryPicker({ id, label, value, countries, onChange, onUnresolvedChange }: CountryPickerProps) {
  const [query, setQuery] = useState('');
  const codes = toCodes(value);
  const byCode = new Map(countries.map((c) => [c.code, c]));
  const available = countries.filter((c) => !codes.includes(c.code));

  const add = (code: string) => {
    if (!codes.includes(code)) onChange([...codes, code].join(','));
    setQuery('');
  };

  const remove = (code: string) => onChange(codes.filter((c) => c !== code).join(','));

  // Without the list (it failed to load) any two-letter code is accepted; the backend rejects unknown ones.
  const resolve = (text: string): string | undefined => {
    const typed = text.trim().toLowerCase();
    if (!typed) return undefined;
    const match = countries.find((c) => optionLabel(c).toLowerCase() === typed)
      ?? countries.find((c) => c.code.toLowerCase() === typed || c.name.toLowerCase() === typed);
    if (match) return match.code;
    if (countries.length === 0 && /^[a-z]{2}$/.test(typed)) return typed.toUpperCase();
    return undefined;
  };

  const handleChange = (text: string) => {
    const match = available.find((c) => optionLabel(c) === text);
    if (match) add(match.code);
    else setQuery(text);
  };

  const commit = () => {
    const code = resolve(query);
    if (code) add(code);
  };

  const unresolved = query.trim() !== '' && resolve(query) === undefined;

  useEffect(() => {
    onUnresolvedChange(unresolved);
    return () => onUnresolvedChange(false);
  }, [unresolved, onUnresolvedChange]);

  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300">
        {label}
      </label>
      {codes.length > 0 && (
        <ul className="mt-1 flex flex-wrap gap-2">
          {codes.map((code) => {
            const country = byCode.get(code);
            return (
              <li
                key={code}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300"
              >
                {country ? optionLabel(country) : code}
                <button
                  type="button"
                  onClick={() => remove(code)}
                  aria-label={`Remove ${country?.name ?? code}`}
                  className="ml-1 rounded hover:bg-blue-200 dark:hover:bg-blue-800/50 focus:outline-none focus:ring-2 focus:ring-blue-500 px-1"
                >
                  &times;
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <input
        type="text"
        id={id}
        list={`${id}-options`}
        autoComplete="off"
        placeholder="Type a country name or code"
        value={query}
        onChange={(e) => handleChange(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            commit();
          }
        }}
        className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
      />
      {unresolved && (
        <p role="alert" className="mt-1 text-xs text-amber-700 dark:text-amber-400">
          No matching country
        </p>
      )}
      <datalist id={`${id}-options`}>
        {available.map((c) => (
          <option key={c.code} value={optionLabel(c)} />
        ))}
      </datalist>
    </div>
  );
}
