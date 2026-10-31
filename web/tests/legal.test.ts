import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { languages } from '../src/lib/i18n';
import { LEGAL_UPDATED, legal, operator } from '../src/lib/legal';

const UNFILLED = /DA COMPILARE/;

function text(doc: { title: string; sections: readonly { heading: string; body: readonly string[] }[] }): string {
  return [doc.title, ...doc.sections.flatMap((s) => [s.heading, ...s.body])].join('\n');
}

describe('legal', () => {
  it('terms and privacy exist in every language, with the same sections', () => {
    expect(Object.keys(legal).sort()).toEqual([...languages].sort());
    for (const kind of ['terms', 'privacy'] as const) {
      const count = legal.it[kind].sections.length;
      expect(count).toBeGreaterThan(5);
      for (const language of languages) {
        const doc = legal[language][kind];
        expect(doc.title.trim()).not.toBe('');
        expect(doc.sections, `${language} ${kind}`).toHaveLength(count);
        for (const section of doc.sections) {
          expect(section.heading.trim()).not.toBe('');
          expect(section.body.length).toBeGreaterThan(0);
          for (const paragraph of section.body) expect(paragraph.trim()).not.toBe('');
        }
      }
    }
  });

  it('no language is a copy of another', () => {
    for (const a of languages) {
      for (const b of languages) {
        if (a !== b) {
          expect(legal[a].terms.title).not.toBe(legal[b].terms.title);
          expect(text(legal[a].privacy)).not.toBe(text(legal[b].privacy));
        }
      }
    }
  });

  it('every language names the operator, the one processor and the code licence', () => {
    for (const language of languages) {
      const terms = text(legal[language].terms);
      const privacy = text(legal[language].privacy);
      for (const doc of [terms, privacy]) {
        expect(doc).toContain(operator.name);
        expect(doc).toContain(operator.email);
      }
      expect(terms).toContain('Apache License 2.0');
      expect(terms).toContain('sigylo.net');
      expect(privacy).toContain('Cloudflare');
      expect(privacy).toContain('Durable Object');
      expect(privacy).not.toContain('Supabase');
      expect(privacy).not.toContain('eu-central-1');
      expect(privacy).not.toContain('PostgreSQL');
      expect(privacy).toContain('SHA-256');
      expect(privacy).toMatch(/\b7\b/);
      expect(privacy).toMatch(/2016\/679/);
    }
  });

  it('says what the relay really does with the address and how long removed data lingers', () => {
    const toml = readFileSync(new URL('../../worker/wrangler.toml', import.meta.url), 'utf8');
    const limit = (name: string) => toml.match(new RegExp(`name = "${name}"[\\s\\S]*?limit = (\\d+)`))?.[1];
    expect([limit('WRITE_LIMITER'), limit('READ_LIMITER')]).toEqual(['30', '60']);
    // A cron every 15 minutes, and garbage waits 5 minutes for the next one: up to 30.
    expect(toml).toContain('crons = ["*/15 * * * *"]');
    const halfHour = { it: "mezz'ora", en: 'half an hour', fr: 'demi-heure', es: 'media hora', de: 'halben Stunde' };
    for (const language of languages) {
      const privacy = text(legal[language].privacy);
      expect(privacy, language).toMatch(/\b30\b[^.]*\b60\b/);
      expect(privacy, language).toContain('/64');
      expect(privacy, language).toContain('/48');
      expect(privacy, language).toContain(halfHour[language]);
    }
  });

  it('keeps accounts in the vault: no database, sign-ins in memory only, 30 days of recovery history', () => {
    const words = {
      it: { database: 'database', disk: 'su disco', history: '30 giorni', closing: 'chiusura' },
      en: { database: 'database', disk: 'to disk', history: '30 days', closing: 'closing' },
      fr: { database: 'base de données', disk: 'sur disque', history: '30 jours', closing: 'fermeture' },
      es: { database: 'base de datos', disk: 'en disco', history: '30 días', closing: 'cierre' },
      de: { database: 'Datenbank', disk: 'Datenträger', history: '30 Tage', closing: 'Schließen' },
    };
    for (const language of languages) {
      const privacy = text(legal[language].privacy);
      const { database, disk, history, closing } = words[language];
      expect(privacy.toLowerCase(), language).not.toContain(database.toLowerCase());
      expect(privacy, language).toContain(disk);
      expect(privacy, language).toContain(history);
      expect(privacy, language).toContain(closing);
      expect(privacy, language).toContain('OPAQUE');
    }
  });

  it('says everything the recovery history keeps, and that closing an account leaves it there', () => {
    // Sections share their order in every language (first test), so the English headings find them.
    const at = (heading: string) => legal.en.privacy.sections.findIndex((s) => s.heading === heading);
    const [retention, provider, rights] = [at('For how long'), at('Provider and transfers'), at('Your rights')];
    expect(Math.min(retention, provider, rights)).toBeGreaterThanOrEqual(0);
    const words = {
      it: { keys: 'chiavi pubbliche', names: 'nomi degli oggetti', history: '30 giorni' },
      en: { keys: 'public keys', names: 'object names', history: '30 days' },
      fr: { keys: 'clés publiques', names: 'noms des objets', history: '30 jours' },
      es: { keys: 'claves públicas', names: 'nombres de los objetos', history: '30 días' },
      de: { keys: 'öffentlichen Schlüssel', names: 'Objektnamen', history: '30 Tage' },
    };
    for (const language of languages) {
      const sections = legal[language].privacy.sections;
      const section = (i: number) => sections[i]!.body.join('\n');
      const { keys, names, history } = words[language];
      // Each request record, with the recipient's public key, sits in SigyloVault's storage.
      expect(section(retention), language).toContain(keys);
      expect(section(retention), language).toContain(names);
      expect(section(provider), language).toContain(keys);
      expect(section(provider), language).toContain(names);
      expect(section(rights), language).toContain(history);
    }
  });

  it('never claims there is no creation time: the expiry and the storage provider give it away', () => {
    // The expiry is kept to the second and the interface offers a handful of
    // lifetimes, so the sealing time follows; R2 and the Durable Objects'
    // recovery history also date every write.
    const absolute = {
      it: /né orario di creazione|nessun orario di creazione/i,
      en: /no creation time/i,
      fr: /ni heure de création|aucune heure de création/i,
      es: /ni hora de creación|ninguna hora de creación/i,
      de: /keine Erstellungszeit/i,
    };
    const derived = { it: 'ricavare', en: 'worked out', fr: 'déduire', es: 'deducirse', de: 'ableiten' };
    const at = legal.en.privacy.sections.findIndex((s) => s.heading === 'What we keep');
    expect(at).toBeGreaterThanOrEqual(0);
    for (const language of languages) {
      expect(text(legal[language].privacy), language).not.toMatch(absolute[language]);
      const kept = legal[language].privacy.sections[at]!.body.join('\n');
      expect(kept, language).toContain(derived[language]);
      expect(kept, language).toContain('Cloudflare');
    }
  });

  it('carries a real date of last update', () => {
    expect(LEGAL_UPDATED).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(Number.isNaN(Date.parse(LEGAL_UPDATED))).toBe(false);
  });

  describe('adversary', () => {
    it('is plain text: no markup that would tempt anyone to render it as HTML', () => {
      for (const language of languages) {
        for (const kind of ['terms', 'privacy'] as const) {
          expect(text(legal[language][kind])).not.toMatch(/[<>]/);
        }
      }
    });

    it('nothing in the client is ever rendered as raw HTML', () => {
      const dir = new URL('../src/components/', import.meta.url);
      const sources = [new URL('../src/App.svelte', import.meta.url), ...readdirSync(dir).map((f) => new URL(f, dir))];
      for (const file of sources) expect(readFileSync(file, 'utf8'), file.pathname).not.toContain('{@html');
    });

    it('the operator and the NOTICE are filled in before anything ships', () => {
      expect(operator.name).not.toMatch(UNFILLED);
      expect(operator.email).toMatch(/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i);
      const notice = readFileSync(new URL('../../NOTICE', import.meta.url), 'utf8');
      expect(notice).not.toMatch(UNFILLED);
      expect(notice).toContain('Apache License, Version 2.0');
    });

    it('security.txt (RFC 9116) names the operator and has not expired', () => {
      const txt = readFileSync(new URL('../public/.well-known/security.txt', import.meta.url), 'utf8');
      expect(txt).toContain(`Contact: mailto:${operator.email}\n`);
      expect(txt).toContain('Canonical: https://sigylo.net/.well-known/security.txt\n');
      const expires = Date.parse(/^Expires: (\S+)$/m.exec(txt)?.[1] ?? '');
      // An expired file fails the CI, and so the deploy, until a new date is set.
      expect(expires).toBeGreaterThan(Date.now());
      expect(expires - Date.now()).toBeLessThan(400 * 24 * 3600 * 1000);
    });
  });
});
