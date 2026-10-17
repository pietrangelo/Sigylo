// Where the client runs. On sigylo.net it talks to its own origin. Inside the
// installable app (a Tauri shell, `vite build --mode app`) the page and the
// Wasm engine ship with the app, the page has no network access at all, and
// every relay call goes through one narrow command of the Rust shell, which
// only knows the relay API on https://sigylo.net.

/** The public site: links made in the app must open for anyone in a browser. */
export const WEB_ORIGIN = 'https://sigylo.net';

export type Invoke = (cmd: string, args: Record<string, unknown>) => Promise<unknown>;
export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

const API = '/api/';

/** A fetch for the relay client that crosses into the app shell instead of the network. */
export function ipcFetch(invoke: Invoke): Fetch {
  return async (input, init) => {
    if (!input.startsWith(API)) throw new TypeError('not a relay call');
    const body = init.body ?? null;
    if (body !== null && typeof body !== 'string') throw new TypeError('relay bodies are JSON text');
    const reply = (await invoke('relay', { method: init.method ?? 'GET', path: input.slice(API.length - 1), body })) as { status?: unknown; body?: unknown } | null;
    const status = reply?.status;
    if (typeof status !== 'number' || !Number.isInteger(status) || status < 200 || status > 599 || typeof reply?.body !== 'string') {
      throw new TypeError('malformed reply from the app shell');
    }
    return new Response(reply.body, { status, headers: { 'Content-Type': 'application/json' } });
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
