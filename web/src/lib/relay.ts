// Client of the blind relay. It only ever sends envelopes that were sealed
// on this device. Opening is a POST, never a GET, so link previews and
// prefetchers cannot burn a secret. Ids are chosen by the relay, never here:
// a burned link can then never be refilled by whoever read it first.
// Account calls carry OPAQUE messages only, never a password, and a session
// travels as a bearer token in the Authorization header.
//
// A file is its sealed manifest (deposited like any envelope, with a chunk
// count) followed by its sealed chunks, which travel as raw bytes.

import { decode, decodeExact, encode } from './base64url';
import { ID_LEN } from './links';

export type Retention = 'burn_after_reading' | 'until_expiry';

export type RelayError =
  | 'NotFound'
  | 'AlreadyExists'
  | 'RateLimited'
  | 'PayloadTooLarge'
  | 'VaultUnavailable'
  | 'NotAuthentic'
  | 'Unauthorized'
  | 'AlreadyRegistered'
  | 'Conflict'
  | 'Throttled'
  | 'InvalidUsername'
  | 'NotConfigured'
  | 'StoreUnavailable'
  | 'StorageFull'
  | 'Network'
  | 'Unexpected';

export type Result<T> = { ok: true; value: T } | { ok: false; error: RelayError };

/** Where the relay put a deposit or request, and until when. */
export type Receipt = { id: Uint8Array; expiresAt: number };

/** An opened deposit. A file adds its chunk count and, if it burns, the claim that releases its chunks. */
export type Opened = { envelope: Uint8Array; burned: boolean; chunks?: number; claim?: Uint8Array };

export const CLAIM_LEN = 32;

type Fetch = (input: string, init: RequestInit) => Promise<Response>;

const KNOWN: ReadonlySet<string> = new Set([
  'NotFound',
  'AlreadyExists',
  'RateLimited',
  'PayloadTooLarge',
  'VaultUnavailable',
  'NotAuthentic',
  'Unauthorized',
  'AlreadyRegistered',
  'Conflict',
  'Throttled',
  'InvalidUsername',
  'NotConfigured',
  'StoreUnavailable',
  'StorageFull',
]);

/** A live session: the bearer token and when the relay ends it. */
export type SessionGrant = { token: Uint8Array; expiresAt: number };

/** The account's keyring as stored: a sealed envelope (or none yet) and its version. */
export type StoredKeyring = { keyring: Uint8Array | null; version: number };


const BASE_INIT: RequestInit = { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' };

export class Relay {
  constructor(
    private readonly fetchImpl: Fetch = (input, init) => fetch(input, init),
    private readonly base = '/api',
  ) {}

  private async send(method: 'GET' | 'POST', path: string, init: RequestInit): Promise<Response | null> {
    try {
      return await this.fetchImpl(`${this.base}${path}`, { ...BASE_INIT, method, ...init });
    } catch {
      return null;
    }
  }

  private static async failure(response: Response): Promise<RelayError> {
    const json: unknown = await response.json().catch(() => null);
    const code = (json as { error?: unknown } | null)?.error;
    return typeof code === 'string' && KNOWN.has(code) ? (code as RelayError) : 'Unexpected';
  }

  private async call<T>(
    method: 'GET' | 'POST',
    path: string,
    body: unknown,
    read: (json: unknown) => T | null,
    session?: Uint8Array,
  ): Promise<Result<T>> {
    const init: RequestInit = {};
    const headers: Record<string, string> = {};
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    if (session !== undefined) headers['Authorization'] = `Bearer ${encode(session)}`;
    if (Object.keys(headers).length > 0) init.headers = headers;
    const response = await this.send(method, path, init);
    if (response === null) return { ok: false, error: 'Network' };
    if (!response.ok) return { ok: false, error: await Relay.failure(response) };
    const json: unknown = await response.json().catch(() => null);
    const value = read(json);
    return value === null ? { ok: false, error: 'Unexpected' } : { ok: true, value };
  }

  /** `chunks` makes the envelope a file's manifest: that many chunks must follow. */
  deposit(envelope: Uint8Array, retention: Retention, lifetimeSeconds: number, revocationToken: Uint8Array, chunks?: number): Promise<Result<Receipt>> {
    return this.call('POST', '/secrets', {
      payload: encode(envelope),
      retention,
      lifetime_seconds: lifetimeSeconds,
      revocation_token: encode(revocationToken),
      ...(chunks === undefined ? {} : { chunks }),
    }, readReceipt);
  }

  open(id: Uint8Array): Promise<Result<Opened>> {
    return this.call('POST', `/secrets/${encode(id)}/open`, undefined, (json) => {
      const j = json as { payload?: unknown; burned?: unknown; chunks?: unknown; claim?: unknown } | null;
      const envelope = typeof j?.payload === 'string' ? decode(j.payload) : null;
      if (envelope === null || typeof j?.burned !== 'boolean') return null;
      if (j.chunks === undefined && j.claim === undefined) return { envelope, burned: j.burned };
      if (typeof j.chunks !== 'number' || !Number.isInteger(j.chunks) || j.chunks < 1) return null;
      if (j.claim === undefined) return { envelope, burned: j.burned, chunks: j.chunks };
      const claim = typeof j.claim === 'string' ? decodeExact(j.claim, CLAIM_LEN) : null;
      return claim === null ? null : { envelope, burned: j.burned, chunks: j.chunks, claim };
    });
  }

  /** Uploads one sealed chunk as the raw request body. */
  async putChunk(id: Uint8Array, index: number, chunk: Uint8Array): Promise<Result<true>> {
    const init: RequestInit = { headers: { 'Content-Type': 'application/octet-stream' }, body: chunk as BodyInit };
    const response = await this.send('POST', `/secrets/${encode(id)}/chunks/${index}`, init);
    if (response === null) return { ok: false, error: 'Network' };
    return response.ok ? { ok: true, value: true } : { ok: false, error: await Relay.failure(response) };
  }

  /** Fetches one sealed chunk; a burn-after-reading file needs the claim from `open`. */
  async openChunk(id: Uint8Array, index: number, claim?: Uint8Array): Promise<Result<Uint8Array>> {
    const body = JSON.stringify(claim === undefined ? {} : { claim: encode(claim) });
    const response = await this.send('POST', `/secrets/${encode(id)}/chunks/${index}/open`, { headers: { 'Content-Type': 'application/json' }, body });
    if (response === null) return { ok: false, error: 'Network' };
    if (!response.ok) return { ok: false, error: await Relay.failure(response) };
    const bytes = await response.arrayBuffer().catch(() => null);
    return bytes === null || bytes.byteLength === 0 ? { ok: false, error: 'Unexpected' } : { ok: true, value: new Uint8Array(bytes) };
  }

  revoke(id: Uint8Array, token: Uint8Array): Promise<Result<true>> {
    return this.call('POST', `/secrets/${encode(id)}/revoke`, { token: encode(token) }, () => true as const);
  }

  postRequest(publicKey: Uint8Array, lifetimeSeconds: number): Promise<Result<Receipt>> {
    return this.call('POST', '/requests', { recipient_key: encode(publicKey), lifetime_seconds: lifetimeSeconds }, readReceipt);
  }

  fetchRequest(id: Uint8Array): Promise<Result<{ publicKey: Uint8Array; expiresAt: number }>> {
    return this.call('GET', `/requests/${encode(id)}`, undefined, (json) => {
      const j = json as { recipient_key?: unknown; expires_at?: unknown } | null;
      const publicKey = typeof j?.recipient_key === 'string' ? decode(j.recipient_key) : null;
      return publicKey !== null && typeof j?.expires_at === 'number' ? { publicKey, expiresAt: j.expires_at } : null;
    });
  }

  answer(id: Uint8Array, envelope: Uint8Array, retention: Retention, lifetimeSeconds: number, chunks?: number): Promise<Result<number>> {
    return this.call('POST', `/requests/${encode(id)}/answer`, {
      payload: encode(envelope),
      retention,
      lifetime_seconds: lifetimeSeconds,
      ...(chunks === undefined ? {} : { chunks }),
    }, readExpires);
  }

  registerStart(username: string, request: Uint8Array): Promise<Result<Uint8Array>> {
    return this.call('POST', '/account/register/start', { username, request: encode(request) }, (json) => field(json, 'response'));
  }

  registerFinish(username: string, record: Uint8Array): Promise<Result<true>> {
    return this.call('POST', '/account/register/finish', { username, record: encode(record) }, () => true as const);
  }

  loginStart(username: string, request: Uint8Array): Promise<Result<{ handle: Uint8Array; response: Uint8Array }>> {
    return this.call('POST', '/account/login/start', { username, request: encode(request) }, (json) => {
      const handle = field(json, 'handle');
      const response = field(json, 'response');
      return handle !== null && response !== null ? { handle, response } : null;
    });
  }

  loginFinish(handle: Uint8Array, finalization: Uint8Array): Promise<Result<SessionGrant>> {
    return this.call('POST', '/account/login/finish', { handle: encode(handle), finalization: encode(finalization) }, (json) => {
      const j = json as { session?: unknown; expires_at?: unknown } | null;
      const token = typeof j?.session === 'string' ? decodeExact(j.session, 32) : null;
      return token !== null && typeof j?.expires_at === 'number' ? { token, expiresAt: j.expires_at } : null;
    });
  }

  logout(session: Uint8Array): Promise<Result<true>> {
    return this.call('POST', '/account/logout', undefined, () => true as const, session);
  }

  readKeyring(session: Uint8Array): Promise<Result<StoredKeyring>> {
    return this.call('GET', '/account/keyring', undefined, (json) => {
      const j = json as { keyring?: unknown; version?: unknown } | null;
      if (typeof j?.version !== 'number' || !Number.isSafeInteger(j.version) || j.version < 0) return null;
      if (j.keyring === null) return { keyring: null, version: j.version };
      const keyring = typeof j.keyring === 'string' ? decode(j.keyring) : null;
      return keyring !== null ? { keyring, version: j.version } : null;
    }, session);
  }

  /** The new version, or `Conflict` when another device wrote since `version` was read. */
  storeKeyring(session: Uint8Array, keyring: Uint8Array, version: number): Promise<Result<number>> {
    return this.call('POST', '/account/keyring', { keyring: encode(keyring), version }, (json) => {
      const v = (json as { version?: unknown } | null)?.version;
      return typeof v === 'number' ? v : null;
    }, session);
  }

  closeAccount(session: Uint8Array): Promise<Result<true>> {
    return this.call('POST', '/account/close', undefined, () => true as const, session);
  }
}

function field(json: unknown, name: string): Uint8Array | null {
  const value = (json as Record<string, unknown> | null)?.[name];
  return typeof value === 'string' ? decode(value) : null;
}

function readReceipt(json: unknown): Receipt | null {
  const j = json as { id?: unknown; expires_at?: unknown } | null;
  const id = typeof j?.id === 'string' ? decodeExact(j.id, ID_LEN) : null;
  return id !== null && typeof j?.expires_at === 'number' ? { id, expiresAt: j.expires_at } : null;
}

function readExpires(json: unknown): number | null {
  const expires = (json as { expires_at?: unknown } | null)?.expires_at;
  return typeof expires === 'number' ? expires : null;
}
