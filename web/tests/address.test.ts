import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// The page reads links from the address and only ever takes them out of it.
// Writing one in would put its key where the browser keeps addresses: the
// History database on disk (Chromium, WebView2 in the app on Windows), the
// session restore files and, with sync on, the account's synced history.
const dirs = ['../src/', '../src/components/', '../src/lib/'].map((d) => new URL(d, import.meta.url));
const sources = dirs.flatMap((dir) =>
  readdirSync(dir)
    .filter((f) => /\.(svelte|ts)$/.test(f))
    .map((f) => ({ name: f, source: readFileSync(new URL(f, dir), 'utf8') })),
);

describe('the address', () => {
  it('the scan covers the pages and the link code', () => {
    const names = sources.map((s) => s.name);
    for (const name of ['App.svelte', 'PasteLink.svelte', 'Opener.svelte', 'links.ts']) expect(names).toContain(name);
  });

  describe('adversary', () => {
    it('no code writes a link into the address: only replaceState to the root takes one out', () => {
      const writes = /location\s*\.\s*(hash|href|search|pathname)\s*=(?!=)|location\s*\.\s*(assign|replace)\s*\(|\blocation\s*=(?!=)|pushState\s*\(|replaceState\s*\((?!null, '', '\/'\))/;
      for (const { name, source } of sources) {
        // Comments may name the APIs; only code counts.
        const code = source.replace(/\/\*[\s\S]*?\*\/|<!--[\s\S]*?-->|(^|[^:])\/\/.*$/gm, '$1');
        expect(code.match(writes)?.[0], name).toBeUndefined();
      }
    });
  });
});
