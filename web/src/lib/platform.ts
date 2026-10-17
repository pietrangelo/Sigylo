// Where the client runs. On sigylo.net it talks to its own origin. Inside the
// installable app (a Tauri shell, `vite build --mode app`) the page and the
// Wasm engine ship with the app, the page has no network access at all, and
// every relay call goes through one narrow command of the Rust shell, which
// only knows the relay API on https://sigylo.net. A file's sealed chunks
// cross into the shell and back in base64url; everything else is JSON text.

import { decode, encode } from './base64url';

/** The public site: links made in the app must open for anyone in a browser. */
export const WEB_ORIGIN = 'https://sigylo.net';

export type Invoke = (cmd: string, args: Record<string, unknown>) => Promise<unknown>;
export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

const API = '/api/';

/** A fetch for the relay client that crosses into the app shell instead of the network. */
export function ipcFetch(invoke: Invoke): Fetch {
  return async (input, init) => {
    if (!input.startsWith(API)) throw new TypeError('not a relay call');
    const raw = init.body ?? null;
    let body: string | null;
    if (raw === null || typeof raw === 'string') body = raw;
    else if (raw instanceof Uint8Array) body = encode(raw);
    else throw new TypeError('relay bodies are JSON text or a sealed chunk');
    const args: Record<string, unknown> = { method: init.method ?? 'GET', path: input.slice(API.length - 1), body };
    const authorization = new Headers(init.headers).get('Authorization');
    if (authorization !== null) {
      // The shell checks the token itself; anything but our own bearer scheme is a bug.
      const session = /^Bearer ([A-Za-z0-9_-]+)$/.exec(authorization)?.[1];
      if (session === undefined) throw new TypeError('unexpected authorization');
      args['session'] = session;
    }
    const reply = (await invoke('relay', args)) as { status?: unknown; body?: unknown; binary?: unknown } | null;
    const status = reply?.status;
    const binary = reply?.binary ?? false;
    if (typeof status !== 'number' || !Number.isInteger(status) || status < 200 || status > 599 || typeof reply?.body !== 'string' || typeof binary !== 'boolean') {
      throw new TypeError('malformed reply from the app shell');
    }
    if (!binary) return new Response(reply.body, { status, headers: { 'Content-Type': 'application/json' } });
    const bytes = decode(reply.body);
    if (bytes === null) throw new TypeError('malformed chunk from the app shell');
    return new Response(bytes as BodyInit, { status, headers: { 'Content-Type': 'application/octet-stream' } });
  };
}

type TauriWindow = { __TAURI_INTERNALS__?: { invoke: Invoke } };

function shellInvoke(): Invoke {
  return (cmd, args) => {
    const internals = (window as unknown as TauriWindow).__TAURI_INTERNALS__;
    return internals ? internals.invoke(cmd, args) : Promise.reject(new Error('not inside the app'));
  };
}

export const isApp = import.meta.env.MODE === 'app';

/** The origin links are built on. */
export const linkOrigin: string = isApp || typeof location === 'undefined' ? WEB_ORIGIN : location.origin;

/** The transport of the relay client, or undefined for the browser's own fetch. */
export const relayFetch: Fetch | undefined = isApp ? ipcFetch(shellInvoke()) : undefined;

/** In the app the terms and the privacy notice open on the site, in the system browser. */
export function openLegal(page: 'terms' | 'privacy'): Promise<unknown> {
  return shellInvoke()('open_legal', { page });
}
