import {
  Field,
  Label,
  Listbox,
  ListboxButton,
  ListboxOptions,
  ListboxOption,
} from '@headlessui/react';
import { ChevronUpDownIcon, CheckIcon } from '@heroicons/react/20/solid';

export interface SelectOption<T extends string> {
  value: T;
  label: string;
}

interface SelectProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: SelectOption<T>[];
  label?: string;
  hint?: string;
}

export function Select<T extends string>({
  value,
  onChange,
  options,
  label,
  hint,
}: SelectProps<T>) {
  const selected = options.find((o) => o.value === value);

  return (
    <Field>
      {label && (
        <Label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          {label}
        </Label>
      )}
      <Listbox value={value} onChange={onChange}>
        <div className="relative mt-1">
          <ListboxButton className="relative w-full cursor-pointer rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 py-2 pl-3 pr-10 text-left text-gray-900 dark:text-white shadow-sm sm:text-sm hover:border-gray-400 dark:hover:border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
            <span className="block truncate">{selected?.label ?? value}</span>
            <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
              <ChevronUpDownIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
            </span>
          </ListboxButton>
          <ListboxOptions
            transition
            className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-md bg-white dark:bg-gray-700 py-1 text-sm shadow-lg ring-1 ring-black/5 dark:ring-white/10 focus:outline-none transition data-[closed]:opacity-0 data-[leave]:duration-75 data-[enter]:duration-100"
          >
            {options.map((opt) => (
              <ListboxOption
                key={opt.value}
                value={opt.value}
                className="group relative cursor-pointer select-none py-2 pl-9 pr-4 text-gray-900 dark:text-gray-100 data-[focus]:bg-blue-100 dark:data-[focus]:bg-blue-900/50 data-[focus]:text-blue-900 dark:data-[focus]:text-blue-100"
              >
                <span className="block truncate font-normal group-data-[selected]:font-medium">
                  {opt.label}
                </span>
                <span className="absolute inset-y-0 left-0 hidden items-center pl-2 text-blue-600 dark:text-blue-400 group-data-[selected]:flex">
                  <CheckIcon className="h-5 w-5" aria-hidden="true" />
                </span>
              </ListboxOption>
            ))}
          </ListboxOptions>
        </div>
      </Listbox>
      {hint && (
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{hint}</p>
      )}
    </Field>
  );
}
