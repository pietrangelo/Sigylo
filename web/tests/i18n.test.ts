import { describe, expect, it } from 'vitest';
import { catalogs, pickLanguage } from '../src/lib/i18n';

describe('i18n', () => {
  it('every message exists and is non-empty in every language', () => {
    const keys = Object.keys(catalogs.it).sort();
    for (const catalog of Object.values(catalogs)) {
      expect(Object.keys(catalog).sort()).toEqual(keys);
      for (const value of Object.values(catalog)) expect(value.trim()).not.toBe('');
    }
  });

  it('follows the browser, Italian first, English otherwise', () => {
    expect(pickLanguage(['it-IT', 'en'])).toBe('it');
    expect(pickLanguage(['en-GB', 'it'])).toBe('it');
    expect(pickLanguage(['de-DE'])).toBe('en');
    expect(pickLanguage([])).toBe('en');
  });
});
