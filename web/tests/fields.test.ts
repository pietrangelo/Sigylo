import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// A read-only field shows something the page made: an opened secret, a new
// link with its key. Firefox's session store writes form field values to disk
// (sessionstore.jsonlz4) unless the field opts out with autocomplete="off".
const dir = new URL('../src/components/', import.meta.url);
const components = readdirSync(dir)
  .filter((f) => f.endsWith('.svelte'))
  .map((f) => ({ name: f, source: readFileSync(new URL(f, dir), 'utf8') }));

function readonlyFields(source: string): string[] {
  // An arrow function inside an attribute (`=>`) does not end the tag.
  return [...source.matchAll(/<(?:input|textarea)\b(?:=>|[^>])*>/g)].map((m) => m[0]).filter((tag) => /\sreadonly\b/.test(tag));
}

describe('fields', () => {
  it('the opened secret and the new links are read-only fields', () => {
    const fields = components.flatMap((c) => readonlyFields(c.source).map((tag) => `${c.name} ${tag}`));
    expect(fields.some((f) => f.startsWith('Opener.svelte') && f.includes('data-testid="plaintext"'))).toBe(true);
    expect(fields.some((f) => f.startsWith('LinkBox.svelte'))).toBe(true);
  });

  describe('adversary', () => {
    it('no read-only field is kept by the browser: no autocomplete, no spellcheck', () => {
      for (const { name, source } of components) {
        for (const tag of readonlyFields(source)) {
          expect(tag, name).toContain('autocomplete="off"');
          expect(tag, name).toContain('spellcheck="false"');
        }
      }
    });
  });
});
