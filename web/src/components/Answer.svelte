<script lang="ts">
  import { engine, errorCode, fileName, loadEngine, passphraseBytes, randomBytes, textBytes } from '../lib/crypto';
  import { MAX_FILE_LEN, resumeUpload, startUpload, type Upload } from '../lib/files';
  import { t } from '../lib/i18n';
  import { SEED_LEN, browserStore, loadOrCreateSeed } from '../lib/identity';
  import { relayMessage, sealMessage } from '../lib/messages';
  import { Relay, type Retention } from '../lib/relay';
  import { relayFetch } from '../lib/platform';
  import SealOptions from './SealOptions.svelte';
  import SecretField from './SecretField.svelte';

  let {
    id,
    fingerprint,
    expectedSender,
  }: { id: Uint8Array; fingerprint: Uint8Array; expectedSender: Uint8Array | null } = $props();

  const relay = new Relay(relayFetch);
  let kind: 'text' | 'file' = $state('text');
  let secret = $state('');
  let file: File | null = $state(null);
  let uploading = $state(false);
  // The answer used up the request: chunks that did not all go up wait here for a retry.
  let pending: Upload | null = $state.raw(null);
  let retention: Retention = $state('burn_after_reading');
  let lifetime = $state(86400);
  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let done = $state(false);
  // Every answer is signed with this browser's sender identity.
  const senderSeed = loadOrCreateSeed(browserStore(), () => randomBytes(SEED_LEN));
  let senderCode = $state('');
  // False when the request names another expected sender: answering would only fail.
  let expected = $state(true);

  $effect(() => {
    loadEngine().then(() => {
      senderCode = engine.senderCode(senderSeed.slice());
      expected = expectedSender === null || engine.isExpectedSender(fingerprint, expectedSender, senderSeed.slice());
    });
  });

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
      // Both throw FingerprintMismatch if the relay served a substituted key, and
      // UnexpectedSender if the request expects someone else.
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
          const sealed = engine.sealFileForRecipient(fileName(file.name), contents, publicKey, fingerprint, pass, senderSeed.slice(), expectedSender ?? undefined);
          envelope = sealed.envelope;
          chunks = sealed.chunks as Uint8Array[];
          sealed.free();
        } finally {
          contents.fill(0);
        }
      } else {
        envelope = engine.sealForRecipient(textBytes(secret), publicKey, fingerprint, pass, senderSeed.slice(), expectedSender ?? undefined);
      }
      const result = await relay.answer(id, envelope, retention, lifetime, chunks?.length);
      if (!result.ok) {
        error = result.error === 'NotFound' ? t.requestGone : relayMessage(result.error);
        return;
      }
      // To the inbox the relay just named: the public request id takes no chunks.
      if (chunks !== undefined && !(await push(startUpload(result.value.id, chunks, lifetime)))) return;
      finish();
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
      uploading = false;
    }
  }

  /** Sends what the inbox still lacks; on failure the upload stays here for a retry. */
  async function push(upload: Upload): Promise<boolean> {
    uploading = true;
    const result = await resumeUpload(relay, upload);
    if (result.ok) {
      pending = null;
      return true;
    }
    // Gone (expired, most likely): the request is used up, only a new one helps.
    pending = result.error === 'NotFound' ? null : upload;
    error = result.error === 'NotFound' ? t.answerUploadGone : relayMessage(result.error);
    return false;
  }

  async function retry() {
    if (pending === null) return;
    busy = true;
    error = '';
    try {
      if (await push(pending)) finish();
    } finally {
      busy = false;
      uploading = false;
    }
  }

  function finish() {
    done = true;
    secret = '';
    file = null;
    passphrase = '';
  }
</script>

<section class="card stack">
  <h2>{t.answerTitle}</h2>
  {#if senderCode}
    <div class="sender">
      <p class="small muted">{t.senderCodeLabel}</p>
      <p class="code" data-testid="sender-code">{senderCode}</p>
      <p class="small muted">{t.senderCodeHint}</p>
    </div>
  {/if}
  {#if done}
    <p class="success" data-testid="answered">{t.answered}</p>
  {:else if pending}
    <p class="error" role="alert" data-testid="answer-error">{error}</p>
    <p class="muted small">{t.uploadStalled}</p>
    <button class="primary" onclick={retry} disabled={busy} data-testid="retry-upload">{uploading ? t.uploading : t.retryUpload}</button>
  {:else if !expected}
    <p class="error" role="alert" data-testid="not-expected">{t.notExpectedSender}</p>
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
