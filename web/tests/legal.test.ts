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

  it('every language names the operator, the processors and the code licence', () => {
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
      expect(privacy).toContain('Supabase');
      expect(privacy).toContain('eu-central-1');
      expect(privacy).toContain('SHA-256');
      expect(privacy).toMatch(/\b7\b/);
      expect(privacy).toMatch(/2016\/679/);
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
  });
});
