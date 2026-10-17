// Subresource Integrity for everything the page loads.
//
// * `virtual:wasm-integrity` exports the sha384 of the Wasm engine, which
//   `src/lib/crypto.ts` passes to fetch() so the browser verifies it.
// * After bundling, every <script>, modulepreload and stylesheet tag in
//   index.html gets an `integrity` attribute computed from the emitted file.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Plugin } from 'vite';

const VIRTUAL = 'virtual:wasm-integrity';
const RESOLVED = `\0${VIRTUAL}`;

function sri(content: string | Uint8Array): string {
  return `sha384-${createHash('sha384').update(content).digest('base64')}`;
}

export function integrity(wasmPath: string): Plugin {
  return {
    name: 'sigylo-integrity',
    resolveId(id) {
      return id === VIRTUAL ? RESOLVED : null;
    },
    load(id) {
      if (id !== RESOLVED) return null;
      this.addWatchFile(wasmPath);
      return `export default ${JSON.stringify(sri(readFileSync(wasmPath)))};`;
    },
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        const bundle = ctx.bundle;
        if (!bundle) return html;
        return html.replace(/<(script|link)\b([^>]*?)\s(src|href)="\/?([^"]+)"([^>]*)>/g, (tag, name, before, attr, file, after) => {
          const output = bundle[file];
          if (!output) return tag;
          const content = output.type === 'chunk' ? output.code : output.source;
          return `<${name}${before} ${attr}="/${file}" integrity="${sri(content)}"${after}>`;
        });
      },
    },
  };
}
