<script lang="ts">
  import { engine, errorCode, fileName, loadEngine, passphraseBytes, textBytes } from '../lib/crypto';
  import { MAX_FILE_LEN, uploadChunks } from '../lib/files';
  import { t } from '../lib/i18n';
  import { relayMessage, sealMessage } from '../lib/messages';
  import { Relay, type Retention } from '../lib/relay';
  import { relayFetch } from '../lib/platform';
  import SealOptions from './SealOptions.svelte';
  import SecretField from './SecretField.svelte';

  let { id, fingerprint }: { id: Uint8Array; fingerprint: Uint8Array } = $props();

  const relay = new Relay(relayFetch);
  let kind: 'text' | 'file' = $state('text');
  let secret = $state('');
  let file: File | null = $state(null);
  let uploading = $state(false);
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
      // Both throw FingerprintMismatch if the relay served a substituted key.
      const { publicKey } = request.value;
      const pass = passphraseBytes(passphrase);
      let envelope: Uint8Array;
      let chunks: Uint8Array[] | undefined;
      if (kind === 'file') {
        if (file === null) return;
        if (file.size > MAX_FILE_LEN) {
          error = t.errFileTooLarge;
          return;
        }
        const contents = new Uint8Array(await file.arrayBuffer());
        try {
          const sealed = engine.sealFileForRecipient(fileName(file.name), contents, publicKey, fingerprint, pass);
          envelope = sealed.envelope;
          chunks = sealed.chunks as Uint8Array[];
          sealed.free();
        } finally {
          contents.fill(0);
        }
      } else {
        envelope = engine.sealForRecipient(textBytes(secret), publicKey, fingerprint, pass);
      }
      const result = await relay.answer(id, envelope, retention, lifetime, chunks?.length);
      if (!result.ok) {
        error = result.error === 'NotFound' ? t.requestGone : relayMessage(result.error);
        return;
      }
      if (chunks !== undefined) {
        uploading = true;
        const uploaded = await uploadChunks(relay, id, chunks);
        if (!uploaded.ok) {
          error = relayMessage(uploaded.error);
          return;
        }
      }
      done = true;
      secret = '';
      file = null;
      passphrase = '';
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
      uploading = false;
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
      <SecretField id="answer-secret" bind:kind bind:text={secret} bind:file />
      <SealOptions bind:retention bind:lifetime bind:passphrase />
      {#if error}<p class="error" role="alert" data-testid="answer-error">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="answer">{uploading ? t.uploading : busy ? t.sealing : t.answer}</button>
    </form>
  {/if}
</section>
