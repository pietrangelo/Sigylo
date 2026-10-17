// Client of the blind relay. It only ever sends envelopes that were sealed
// on this device. Opening is a POST, never a GET, so link previews and
// prefetchers cannot burn a secret. Ids are chosen by the relay, never here:
// a burned link can then never be refilled by whoever read it first.

import { decode, decodeExact, encode } from './base64url';
import { ID_LEN } from './links';

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

/** Where the relay put a deposit, and until when. */
export type Receipt = { id: Uint8Array; expiresAt: number };

/**
 * Where the relay put a request: the public id for the sender's link, and the
 * private inbox where the answer will be filed, for the recipient's link only.
 */
export type RequestReceipt = { id: Uint8Array; inbox: Uint8Array; expiresAt: number };

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

  deposit(envelope: Uint8Array, retention: Retention, lifetimeSeconds: number, revocationToken: Uint8Array): Promise<Result<Receipt>> {
    return this.call('POST', '/secrets', {
      payload: encode(envelope),
      retention,
      lifetime_seconds: lifetimeSeconds,
      revocation_token: encode(revocationToken),
    }, readReceipt);
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

  postRequest(publicKey: Uint8Array, lifetimeSeconds: number): Promise<Result<RequestReceipt>> {
    return this.call('POST', '/requests', { recipient_key: encode(publicKey), lifetime_seconds: lifetimeSeconds }, readRequestReceipt);
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

function readReceipt(json: unknown): Receipt | null {
  const j = json as { id?: unknown; expires_at?: unknown } | null;
  const id = typeof j?.id === 'string' ? decodeExact(j.id, ID_LEN) : null;
  return id !== null && typeof j?.expires_at === 'number' ? { id, expiresAt: j.expires_at } : null;
}

function readRequestReceipt(json: unknown): RequestReceipt | null {
  const receipt = readReceipt(json);
  const inboxText = (json as { inbox?: unknown } | null)?.inbox;
  const inbox = typeof inboxText === 'string' ? decodeExact(inboxText, ID_LEN) : null;
  // An inbox equal to the public id would let the request link reach the answer.
  if (receipt === null || inbox === null || encode(inbox) === encode(receipt.id)) return null;
  return { id: receipt.id, inbox, expiresAt: receipt.expiresAt };
}

function readExpires(json: unknown): number | null {
  const expires = (json as { expires_at?: unknown } | null)?.expires_at;
  return typeof expires === 'number' ? expires : null;
}
