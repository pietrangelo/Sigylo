// `vite build --mode app` builds the page bundled in the Tauri app. Its
// policy forbids every network connection: 'self' is the app's own bundle
// (the Wasm engine), and the only way out is the app shell's IPC, whose relay
// command knows nothing but the sigylo.net API.

import type { Plugin } from 'vite';

const CONNECT = "connect-src 'self';";

export function appCsp(html: string): string {
  if (!html.includes(CONNECT)) throw new Error('index.html has no connect-src to restrict');
  return html.replace(CONNECT, "connect-src 'self' ipc: http://ipc.localhost;");
}

export function app(): Plugin {
  return {
    name: 'sigylo-app',
    apply: (_, env) => env.mode === 'app',
    transformIndexHtml: { order: 'pre', handler: appCsp },
  };
}
