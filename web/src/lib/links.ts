// Links live entirely in the URL fragment (after '#'). Browsers never send
// the fragment to any server, so neither the host serving the page nor the
// relay ever learns the key, the seed or the revocation token.
//
//   #/s/<id>/<key>       open a secret (link mode)
//   #/s/<id>/<key>/p     ... that also needs a passphrase
//   #/x/<id>/<token>     revoke a secret before it is read (sender only)
//   #/r/<id>/<fpr>       answer a request: seal to the recipient's public key
//   #/r/<id>/<fpr>/<pin> ... that only the expected sender may answer
//   #/k/<id>/<seed>      the recipient's private link to read the answer
//   #/k/<id>/<seed>/<pin> ... refusing an answer from anyone but that sender
//   #/me                 this browser's sender code
//   #/terms, #/privacy   the terms of service and the privacy notice
//
// The pin is a per-request commitment to the expected sender's code, never
// the code itself, so links to the same sender cannot be linked together.

import { decodeExact, encode } from './base64url';

export const ID_LEN = 16;
export const KEY_LEN = 32;
export const PIN_LEN = 32;

export type Route =
  | { kind: 'compose' }
  | { kind: 'secret'; id: Uint8Array; key: Uint8Array; passphrase: boolean }
  | { kind: 'revoke'; id: Uint8Array; token: Uint8Array }
  | { kind: 'answer'; id: Uint8Array; fingerprint: Uint8Array; expectedSender: Uint8Array | null }
  | { kind: 'inbox'; id: Uint8Array; seed: Uint8Array; expectedSender: Uint8Array | null }
  | { kind: 'me' }
  | { kind: 'terms' }
  | { kind: 'privacy' }
  | { kind: 'invalid' };

export function parseFragment(fragment: string): Route {
  const path = fragment.replace(/^#/, '');
  if (path === '' || path === '/') return { kind: 'compose' };
  if (path === '/terms') return { kind: 'terms' };
  if (path === '/privacy') return { kind: 'privacy' };
  if (path === '/me') return { kind: 'me' };
  const parts = path.split('/');
  if (parts[0] !== '') return { kind: 'invalid' };
  const [, kind, idText, secretText, flag, ...rest] = parts;
  if (rest.length > 0 || idText === undefined || secretText === undefined) return { kind: 'invalid' };
  const id = decodeExact(idText, ID_LEN);
  const secret = decodeExact(secretText, KEY_LEN);
  if (id === null || secret === null) return { kind: 'invalid' };
  if (kind === 's' && (flag === undefined || flag === 'p')) {
    return { kind: 'secret', id, key: secret, passphrase: flag === 'p' };
  }
  const pin = flag === undefined ? null : decodeExact(flag, PIN_LEN);
  if (flag !== undefined && pin === null) return { kind: 'invalid' };
  switch (kind) {
    case 'x':
      return pin === null ? { kind: 'revoke', id, token: secret } : { kind: 'invalid' };
    case 'r':
      return { kind: 'answer', id, fingerprint: secret, expectedSender: pin };
    case 'k':
      return { kind: 'inbox', id, seed: secret, expectedSender: pin };
    default:
      return { kind: 'invalid' };
  }
}

function link(origin: string, ...parts: string[]): string {
  return `${origin}/#/${parts.join('/')}`;
}

export function secretLink(origin: string, id: Uint8Array, key: Uint8Array, passphrase: boolean): string {
  const parts = ['s', encode(id), encode(key)];
  if (passphrase) parts.push('p');
  return link(origin, ...parts);
}

export function revokeLink(origin: string, id: Uint8Array, token: Uint8Array): string {
  return link(origin, 'x', encode(id), encode(token));
}

export function requestLink(origin: string, id: Uint8Array, fingerprint: Uint8Array, pin?: Uint8Array): string {
  return link(origin, 'r', encode(id), encode(fingerprint), ...(pin ? [encode(pin)] : []));
}

export function inboxLink(origin: string, id: Uint8Array, seed: Uint8Array, pin?: Uint8Array): string {
  return link(origin, 'k', encode(id), encode(seed), ...(pin ? [encode(pin)] : []));
}

const SITE = 'https://sigylo.net';

/**
 * The fragment of a Sigylo link pasted into the app, or null. Only links of
 * the public site that carry a secret, a request or an inbox are accepted:
 * the app never follows a pasted address anywhere else.
 */
export function linkFragment(text: string): string | null {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    return null;
  }
  if (url.origin !== SITE || url.username !== '' || url.password !== '' || url.pathname !== '/' || url.search !== '') return null;
  const kind = parseFragment(url.hash).kind;
  return kind === 'secret' || kind === 'revoke' || kind === 'answer' || kind === 'inbox' ? url.hash : null;
}
