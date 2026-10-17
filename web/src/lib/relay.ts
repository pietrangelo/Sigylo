// Client of the blind relay. It only ever sends envelopes that were sealed
// on this device. Opening is a POST, never a GET, so link previews and
// prefetchers cannot burn a secret.

import { decode, encode } from './base64url';

export type Retention = 'burn_after_reading' | 'until_expiry';

export type RelayError =
  | 'NotFound'
  | 'AlreadyExists'
  | 'RateLimited'
  | 'PayloadTooLarge'
  | 'VaultUnavailable'
  | 'Network'
  | 'Unexpected';

export type Result<T> = { ok: true; value: T } | { ok: false; error: RelayError };

type Fetch = (input: string, init: RequestInit) => Promise<Response>;

const KNOWN: ReadonlySet<string> = new Set(['NotFound', 'AlreadyExists', 'RateLimited', 'PayloadTooLarge', 'VaultUnavailable']);

export class Relay {
  constructor(
    private readonly fetchImpl: Fetch = (input, init) => fetch(input, init),
    private readonly base = '/api',
  ) {}

  private async call<T>(method: 'GET' | 'POST', path: string, body: unknown, read: (json: unknown) => T | null): Promise<Result<T>> {
    let response: Response;
    try {
      const init: RequestInit = { method, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' };
      if (body !== undefined) {
        init.headers = { 'Content-Type': 'application/json' };
        init.body = JSON.stringify(body);
      }
      response = await this.fetchImpl(`${this.base}${path}`, init);
    } catch {
      return { ok: false, error: 'Network' };
    }
    const json: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const code = (json as { error?: unknown } | null)?.error;
      return { ok: false, error: typeof code === 'string' && KNOWN.has(code) ? (code as RelayError) : 'Unexpected' };
    }
    const value = read(json);
    return value === null ? { ok: false, error: 'Unexpected' } : { ok: true, value };
  }

  deposit(id: Uint8Array, envelope: Uint8Array, retention: Retention, lifetimeSeconds: number, revocationToken: Uint8Array): Promise<Result<number>> {
    return this.call('POST', '/secrets', {
      id: encode(id),
      payload: encode(envelope),
      retention,
      lifetime_seconds: lifetimeSeconds,
      revocation_token: encode(revocationToken),
    }, readExpires);
  }

  open(id: Uint8Array): Promise<Result<{ envelope: Uint8Array; burned: boolean }>> {
    return this.call('POST', `/secrets/${encode(id)}/open`, undefined, (json) => {
      const j = json as { payload?: unknown; burned?: unknown } | null;
      const envelope = typeof j?.payload === 'string' ? decode(j.payload) : null;
      return envelope !== null && typeof j?.burned === 'boolean' ? { envelope, burned: j.burned } : null;
    });
  }

  revoke(id: Uint8Array, token: Uint8Array): Promise<Result<true>> {
    return this.call('POST', `/secrets/${encode(id)}/revoke`, { token: encode(token) }, () => true as const);
  }

  postRequest(id: Uint8Array, publicKey: Uint8Array, lifetimeSeconds: number): Promise<Result<number>> {
    return this.call('POST', '/requests', { id: encode(id), recipient_key: encode(publicKey), lifetime_seconds: lifetimeSeconds }, readExpires);
  }

  fetchRequest(id: Uint8Array): Promise<Result<{ publicKey: Uint8Array; expiresAt: number }>> {
    return this.call('GET', `/requests/${encode(id)}`, undefined, (json) => {
      const j = json as { recipient_key?: unknown; expires_at?: unknown } | null;
      const publicKey = typeof j?.recipient_key === 'string' ? decode(j.recipient_key) : null;
      return publicKey !== null && typeof j?.expires_at === 'number' ? { publicKey, expiresAt: j.expires_at } : null;
    });
  }

  answer(id: Uint8Array, envelope: Uint8Array, retention: Retention, lifetimeSeconds: number): Promise<Result<number>> {
    return this.call('POST', `/requests/${encode(id)}/answer`, { payload: encode(envelope), retention, lifetime_seconds: lifetimeSeconds }, readExpires);
  }
}

function readExpires(json: unknown): number | null {
  const expires = (json as { expires_at?: unknown } | null)?.expires_at;
  return typeof expires === 'number' ? expires : null;
}
