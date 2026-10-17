// Optional accounts, with OPAQUE: the password is used only inside the Wasm
// engine on this device, and the relay sees blinded protocol messages. A
// login yields a session token (for the relay) and the keyring key (which
// never leaves this device); the keyring is sealed with it before upload.

import { bytesText, textBytes } from './crypto';
import { EMPTY, parseKeyring, pruneExpired, serializeKeyring, type KeyringData } from './keyring';
import { Relay, type RelayError } from './relay';

/** What a signed-in tab holds, in memory only: a reload signs out. */
export type Session = { username: string; token: Uint8Array; expiresAt: number; keyringKey: Uint8Array };

export type AccountError = RelayError | 'InvalidPassword' | 'KeyringUnreadable';

export type Outcome<T> = { ok: true; value: T } | { ok: false; error: AccountError };

type Pending = { readonly request: Uint8Array; finish(response: Uint8Array): Admission; free(): void };
type Admission = { readonly message: Uint8Array; readonly keyringKey: Uint8Array; free(): void };

/** The parts of the Wasm engine accounts use. */
export type AccountEngine = {
  beginRegistration(password: Uint8Array): Pending;
  beginLogin(password: Uint8Array): Pending;
  sealWithKey(plaintext: Uint8Array, key: Uint8Array): Uint8Array;
  openLink(envelope: Uint8Array, key: Uint8Array, passphrase?: Uint8Array | null): Uint8Array;
};

/** Names are case-insensitive and NFC, so "Élodie" typed anywhere is one account. */
export function normalizeUsername(username: string): string {
  return username.normalize('NFC').trim().toLowerCase();
}

function passwordBytes(password: string): Uint8Array {
  return textBytes(password.normalize('NFC'));
}

function engineFailure(error: unknown): AccountError {
  const code = error instanceof Error ? error.message : '';
  if (code === 'InvalidPassword') return 'InvalidPassword';
  if (code === 'NotAuthentic' || code === 'MalformedMessage') return 'NotAuthentic';
  return 'Unexpected';
}

/** Runs one OPAQUE exchange: start on the device, ask the relay, finish on the device. */
function exchange<T>(
  begin: () => Pending,
  ask: (request: Uint8Array) => Promise<Outcome<{ response: Uint8Array; extra: T }>>,
): Promise<Outcome<{ message: Uint8Array; keyringKey: Uint8Array; extra: T }>> {
  return (async () => {
    let pending: Pending;
    try {
      pending = begin();
    } catch (e) {
      return { ok: false, error: engineFailure(e) };
    }
    try {
      const answer = await ask(pending.request);
      if (!answer.ok) return answer;
      const admission = pending.finish(answer.value.response);
      const value = { message: admission.message, keyringKey: admission.keyringKey, extra: answer.value.extra };
      admission.free();
      return { ok: true, value };
    } catch (e) {
      return { ok: false, error: engineFailure(e) };
    } finally {
      pending.free();
    }
  })();
}

export class Accounts {
  constructor(
    private readonly engine: AccountEngine,
    private readonly relay: Relay = new Relay(),
  ) {}

  /** Creates the account, then signs in (a second OPAQUE run gives the session). */
  async register(username: string, password: string): Promise<Outcome<Session>> {
    const name = normalizeUsername(username);
    const registered = await exchange(
      () => this.engine.beginRegistration(passwordBytes(password)),
      async (request) => {
        const r = await this.relay.registerStart(name, request);
        return r.ok ? { ok: true, value: { response: r.value, extra: null } } : r;
      },
    );
    if (!registered.ok) return registered;
    registered.value.keyringKey.fill(0);
    const filed = await this.relay.registerFinish(name, registered.value.message);
    if (!filed.ok) return filed;
    return this.signIn(name, password);
  }

  async signIn(username: string, password: string): Promise<Outcome<Session>> {
    const name = normalizeUsername(username);
    const login = await exchange(
      () => this.engine.beginLogin(passwordBytes(password)),
      async (request) => {
        const r = await this.relay.loginStart(name, request);
        return r.ok ? { ok: true, value: { response: r.value.response, extra: r.value.handle } } : r;
      },
    );
    if (!login.ok) return login;
    const granted = await this.relay.loginFinish(login.value.extra, login.value.message);
    if (!granted.ok) {
      login.value.keyringKey.fill(0);
      return granted;
    }
    return { ok: true, value: { username: name, ...granted.value, keyringKey: login.value.keyringKey } };
  }

  /** The keyring as stored, opened on this device. */
  async keyring(session: Session): Promise<Outcome<{ data: KeyringData; version: number }>> {
    const stored = await this.relay.readKeyring(session.token);
    if (!stored.ok) return stored;
    if (stored.value.keyring === null) return { ok: true, value: { data: EMPTY, version: stored.value.version } };
    try {
      const data = parseKeyring(bytesText(this.engine.openLink(stored.value.keyring, session.keyringKey)));
      return data === null ? { ok: false, error: 'KeyringUnreadable' } : { ok: true, value: { data, version: stored.value.version } };
    } catch {
      return { ok: false, error: 'KeyringUnreadable' };
    }
  }

  /**
   * Applies `change` to the latest keyring and stores it. When another device
   * wrote in between, it reads again and re-applies the change, so neither
   * device's change is lost.
   */
  async update(session: Session, change: (keyring: KeyringData) => KeyringData): Promise<Outcome<KeyringData>> {
    for (let attempt = 0; attempt < 4; attempt++) {
      const current = await this.keyring(session);
      if (!current.ok) return current;
      const next = change(pruneExpired(current.value.data, Math.floor(Date.now() / 1000)));
      let sealed: Uint8Array;
      try {
        sealed = this.engine.sealWithKey(textBytes(serializeKeyring(next)), session.keyringKey);
      } catch {
        return { ok: false, error: 'Unexpected' };
      }
      const stored = await this.relay.storeKeyring(session.token, sealed, current.value.version);
      if (stored.ok) return { ok: true, value: next };
      if (stored.error !== 'Conflict') return stored;
    }
    return { ok: false, error: 'Conflict' };
  }

  async signOut(session: Session): Promise<void> {
    await this.relay.logout(session.token);
    forget(session);
  }

  /** Deletes the account and its keyring. Secrets already sent stay valid until they expire. */
  async close(session: Session): Promise<Outcome<true>> {
    const closed = await this.relay.closeAccount(session.token);
    if (closed.ok) forget(session);
    return closed;
  }
}

/** Overwrites what the session held in this tab. */
export function forget(session: Session): void {
  session.token.fill(0);
  session.keyringKey.fill(0);
}
