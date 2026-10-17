import { describe, expect, it } from 'vitest';
import { catalogs, languages, pickLanguage } from '../src/lib/i18n';

describe('i18n', () => {
  it('speaks Italian, English, French, Spanish and German', () => {
    expect([...languages].sort()).toEqual(['de', 'en', 'es', 'fr', 'it']);
    expect(Object.keys(catalogs).sort()).toEqual([...languages].sort());
  });

  it('every message exists and is non-empty in every language', () => {
    const keys = Object.keys(catalogs.it).sort();
    for (const catalog of Object.values(catalogs)) {
      expect(Object.keys(catalog).sort()).toEqual(keys);
      for (const value of Object.values(catalog)) expect(value.trim()).not.toBe('');
    }
  });

  it('no language is a copy of another', () => {
    for (const a of languages) {
      for (const b of languages) {
        if (a !== b) expect(catalogs[a].tagline).not.toBe(catalogs[b].tagline);
      }
    }
  });

  it('follows the first browser language it speaks, English otherwise', () => {
    expect(pickLanguage(['it-IT', 'en'])).toBe('it');
    expect(pickLanguage(['en-GB', 'it'])).toBe('en');
    expect(pickLanguage(['fr-CA'])).toBe('fr');
    expect(pickLanguage(['es-419', 'en'])).toBe('es');
    expect(pickLanguage(['DE-at'])).toBe('de');
    expect(pickLanguage(['pt-BR', 'de', 'it'])).toBe('de');
    expect(pickLanguage(['ja'])).toBe('en');
    expect(pickLanguage([])).toBe('en');
  });

  describe('adversary', () => {
    it('a language tag that merely starts like a known one is not matched', () => {
      expect(pickLanguage(['ita', 'fra'])).toBe('en');
      expect(pickLanguage(['e', 'dex'])).toBe('en');
    });

    it('every catalog keeps the product name and the algorithm names intact', () => {
      for (const catalog of Object.values(catalogs)) {
        expect(catalog.home).toBe('Sigylo');
        expect(catalog.footer).toContain('X25519 + ML-KEM-768');
        expect(catalog.footer).toContain('XChaCha20-Poly1305');
      }
    });
  });
});
