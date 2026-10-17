// Turns engine and relay error codes into sentences for people.

import type { SealErrorCode } from './crypto';
import { t } from './i18n';
import type { RelayError } from './relay';

export function sealMessage(code: SealErrorCode): string {
  switch (code) {
    case 'NotAuthentic':
    case 'PassphraseExpectationMismatch':
      return t.errNotAuthentic;
    case 'FingerprintMismatch':
      return t.errFingerprint;
    case 'PlaintextTooLarge':
      return t.errTooLarge;
    case 'PlaintextEmpty':
      return t.errEmpty;
    case 'InvalidSenderCode':
      return t.errSenderCode;
    case 'UnexpectedSender':
      return t.errUnexpectedSender;
    default:
      return t.errGeneric;
  }
}

export function relayMessage(error: RelayError): string {
  switch (error) {
    case 'NotFound':
      return t.gone;
    case 'Network':
    case 'VaultUnavailable':
      return t.errNetwork;
    case 'RateLimited':
      return t.errRateLimited;
    case 'PayloadTooLarge':
      return t.errTooLarge;
    case 'CustodyFull':
      return t.errFull;
    default:
      return t.errGeneric;
  }
}

export function formatExpiry(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(document.documentElement.lang, { dateStyle: 'medium', timeStyle: 'short' });
}
