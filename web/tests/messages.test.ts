import { describe, expect, it } from 'vitest';
import { t } from '../src/lib/i18n';
import { answerMessage, mayHaveArrived } from '../src/lib/messages';
import type { RelayError } from '../src/lib/relay';

describe('messages', () => {
  it('a send that broke off may have arrived; a refusal surely did not', () => {
    for (const error of ['Network', 'Unexpected'] as RelayError[]) expect(mayHaveArrived(error), error).toBe(true);
    for (const error of ['NotFound', 'RateLimited', 'PayloadTooLarge', 'StorageFull', 'NotAuthentic'] as RelayError[]) {
      expect(mayHaveArrived(error), error).toBe(false);
    }
  });

  describe('adversary', () => {
    it('a request "already used" right after a send that broke off is not shown as someone else answering', () => {
      expect(answerMessage('NotFound', false)).toBe(t.requestGone);
      expect(answerMessage('NotFound', true)).toBe(t.answerMaybeSent);
      expect(answerMessage('RateLimited', true)).toBe(t.errRateLimited);
    });
  });
});
