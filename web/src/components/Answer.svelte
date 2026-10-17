<script lang="ts">
  import { engine, errorCode, loadEngine, passphraseBytes, textBytes } from '../lib/crypto';
  import { t } from '../lib/i18n';
  import { relayMessage, sealMessage } from '../lib/messages';
  import { Relay, type Retention } from '../lib/relay';
  import { relayFetch } from '../lib/platform';
  import SealOptions from './SealOptions.svelte';

  let { id, fingerprint }: { id: Uint8Array; fingerprint: Uint8Array } = $props();

  const relay = new Relay(relayFetch);
  let secret = $state('');
  let retention: Retention = $state('burn_after_reading');
  let lifetime = $state(86400);
  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let done = $state(false);

  async function send(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await loadEngine();
      const request = await relay.fetchRequest(id);
      if (!request.ok) {
        error = request.error === 'NotFound' ? t.requestGone : relayMessage(request.error);
        return;
      }
      // Throws FingerprintMismatch if the relay served a substituted key.
      const envelope = engine.sealForRecipient(textBytes(secret), request.value.publicKey, fingerprint, passphraseBytes(passphrase));
      const result = await relay.answer(id, envelope, retention, lifetime);
      if (!result.ok) {
        error = result.error === 'NotFound' ? t.requestGone : relayMessage(result.error);
        return;
      }
      done = true;
      secret = '';
      passphrase = '';
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
    }
  }
</script>

<section class="card stack">
  <h2>{t.answerTitle}</h2>
  {#if done}
    <p class="success" data-testid="answered">{t.answered}</p>
  {:else}
    <p class="muted">{t.answerIntro}</p>
    <form class="stack" onsubmit={send}>
      <div>
        <label for="answer-secret">{t.secretLabel}</label>
        <textarea id="answer-secret" bind:value={secret} placeholder={t.secretPlaceholder} autocomplete="off" spellcheck="false" required data-testid="secret"></textarea>
      </div>
      <SealOptions bind:retention bind:lifetime bind:passphrase />
      {#if error}<p class="error" role="alert" data-testid="answer-error">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="answer">{busy ? t.sealing : t.answer}</button>
    </form>
  {/if}
</section>
