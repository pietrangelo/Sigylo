<script lang="ts">
  import { engine, errorCode, fileName, loadEngine, passphraseBytes, randomBytes, textBytes } from '../lib/crypto';
  import { MAX_FILE_LEN, resumeUpload, startUpload, type Upload } from '../lib/files';
  import { t } from '../lib/i18n';
  import { inboxLink, requestLink, revokeLink, secretLink } from '../lib/links';
  import { formatExpiry, relayMessage, sealMessage } from '../lib/messages';
  import { Relay, type Retention } from '../lib/relay';
  import { Accounts } from '../lib/account';
  import { encode } from '../lib/base64url';
  import { addSeal } from '../lib/keyring';
  import { currentSession } from '../lib/session.svelte';
  import { linkOrigin, relayFetch } from '../lib/platform';
  import LinkBox from './LinkBox.svelte';
  import SealOptions from './SealOptions.svelte';
  import SecretField from './SecretField.svelte';

  const relay = new Relay(relayFetch);
  let tab: 'send' | 'receive' = $state('send');
  let kind: 'text' | 'file' = $state('text');
  let secret = $state('');
  let file: File | null = $state(null);
  let uploading = $state(false);
  // A file whose chunks did not all go up waits here for a retry; `done` shows its links.
  type Stalled = { upload: Upload; token: Uint8Array; done: () => Promise<void> };
  let pending: Stalled | null = $state.raw(null);
  let retention: Retention = $state('burn_after_reading');
  let lifetime = $state(86400);
  // Its own: a request has no five-minute choice.
  let requestLifetime = $state(86400);
  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let sent: { link: string; revoke: string; expires: number; saved: boolean | null } | null = $state(null);
  let requested: { request: string; inbox: string; expires: number } | null = $state(null);
  let expectedCode = $state('');

  async function seal(event: SubmitEvent) {
    event.preventDefault();
    abandon();
    busy = true;
    error = '';
    try {
      await loadEngine();
      const pass = passphraseBytes(passphrase);
      let key: Uint8Array;
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
          const sealed = engine.sealFileForLink(fileName(file.name), contents, pass);
          ({ key, envelope } = sealed);
          chunks = sealed.chunks as Uint8Array[];
          sealed.free();
        } finally {
          contents.fill(0);
        }
      } else {
        const sealed = engine.sealForLink(textBytes(secret), pass);
        ({ key, envelope } = sealed);
        sealed.free();
      }
      const token = randomBytes(32);
      const result = await relay.deposit(envelope, retention, lifetime, token, chunks?.length);
      if (!result.ok) {
        error = relayMessage(result.error);
        return;
      }
      const receipt = result.value;
      const withPass = pass !== undefined;
      const done = async () => {
        sent = {
          link: secretLink(linkOrigin, receipt.id, key, withPass),
          revoke: revokeLink(linkOrigin, receipt.id, token),
          expires: receipt.expiresAt,
          saved: null,
        };
        secret = '';
        file = null;
        passphrase = '';
        await remember(receipt.id, token, receipt.expiresAt);
      };
      if (chunks !== undefined && !(await push({ upload: startUpload(receipt.id, chunks, lifetime), token, done }))) return;
      await done();
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
      uploading = false;
    }
  }

  /** Sends what the deposit still lacks; on failure it stays here for a retry. */
  async function push(stalled: Stalled): Promise<boolean> {
    uploading = true;
    const result = await resumeUpload(relay, stalled.upload);
    if (result.ok) {
      pending = null;
      return true;
    }
    // Gone (expired, most likely): only sealing it again helps.
    pending = result.error === 'NotFound' ? null : stalled;
    error = result.error === 'NotFound' ? t.uploadGone : relayMessage(result.error);
    return false;
  }

  async function retry() {
    const stalled = pending;
    if (stalled === null) return;
    busy = true;
    error = '';
    try {
      if (await push(stalled)) await stalled.done();
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
      uploading = false;
    }
  }

  /** Gives up on a stalled file: nobody can open it, so take the manifest back too. */
  function abandon() {
    if (pending !== null) void relay.revoke(pending.upload.id, pending.token);
    pending = null;
    error = '';
  }

  /** Signed in: keep the revocation token in the account's sealed keyring. */
  async function remember(id: Uint8Array, token: Uint8Array, expires: number) {
    const session = currentSession();
    if (session === null || sent === null) return;
    const seal = { id: encode(id), token: encode(token), sealed: Math.floor(Date.now() / 1000), expires };
    const saved = await new Accounts(engine, relay).update(session, (k) => addSeal(k, seal));
    if (sent !== null) sent.saved = saved.ok;
  }

  async function createRequest(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await loadEngine();
      const recipient = engine.newRecipient();
      const seed = recipient.seed;
      const publicKey = recipient.publicKey;
      const fingerprint = recipient.fingerprint;
      recipient.free();
      // Throws InvalidSenderCode before anything reaches the relay.
      const pin = expectedCode.trim() === '' ? undefined : engine.senderPin(fingerprint, expectedCode);
      const result = await relay.postRequest(publicKey, requestLifetime);
      if (!result.ok) {
        error = relayMessage(result.error);
        return;
      }
      requested = {
        request: requestLink(linkOrigin, result.value.id, fingerprint, pin),
        // The answer is filed in the private inbox, never under the public id.
        inbox: inboxLink(linkOrigin, result.value.inbox, seed, pin),
        expires: result.value.expiresAt,
      };
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
    }
  }

  function reset() {
    abandon();
    sent = null;
  }

  /**
   * Each tab keeps what it made: the links on screen are the only copy of the
   * key (or of the request's seed), so only an explicit "another" drops them.
   */
  function show(next: typeof tab) {
    if (tab === next) return;
    tab = next;
    error = '';
  }
</script>

<section class="card stack">
  <div class="tabs" role="tablist">
    <button role="tab" aria-selected={tab === 'send'} class:active={tab === 'send'} onclick={() => show('send')} data-testid="tab-send">{t.tabSend}</button>
    <button role="tab" aria-selected={tab === 'receive'} class:active={tab === 'receive'} onclick={() => show('receive')} data-testid="tab-receive">{t.tabReceive}</button>
  </div>

  {#if tab === 'send' && sent}
    <div class="stack" data-testid="sent">
      <LinkBox label={t.shareThis} value={sent.link} testid="secret-link" />
      <p class="muted small">{t.expiresAt} {formatExpiry(sent.expires)}</p>
      <LinkBox label={t.keepRevoke} value={sent.revoke} testid="revoke-link" />
      {#if sent.saved === true}<p class="success small" data-testid="saved-to-account">{t.savedToAccount}</p>{/if}
      {#if sent.saved === false}<p class="error small">{t.notSaved}</p>{/if}
      <button class="secondary" onclick={reset}>{t.another}</button>
    </div>
  {:else if tab === 'send' && pending}
    <div class="stack">
      <p class="error" role="alert" data-testid="seal-error">{error}</p>
      <p class="muted small">{t.uploadStalled}</p>
      <button class="primary" onclick={retry} disabled={busy} data-testid="retry-upload">{uploading ? t.uploading : t.retryUpload}</button>
      <button class="secondary" onclick={abandon} disabled={busy}>{t.another}</button>
    </div>
  {:else if tab === 'send'}
    <form class="stack" onsubmit={seal}>
      <SecretField id="secret" bind:kind bind:text={secret} bind:file />
      <SealOptions bind:retention bind:lifetime bind:passphrase />
      {#if error}<p class="error" role="alert" data-testid="seal-error">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="seal">{uploading ? t.uploading : busy ? t.sealing : t.seal}</button>
    </form>
  {:else if requested}
    <div class="stack" data-testid="requested">
      <LinkBox label={t.requestLink} value={requested.request} testid="request-link" />
      <LinkBox label={t.inboxLink} value={requested.inbox} testid="inbox-link" />
      <p class="muted small">{t.expiresAt} {formatExpiry(requested.expires)}</p>
      <button class="secondary" onclick={() => (requested = null)} data-testid="another-request">{t.anotherRequest}</button>
    </div>
  {:else}
    <form class="stack" onsubmit={createRequest}>
      <p>{t.receiveIntro}</p>
      <div>
        <label for="request-lifetime">{t.lifetime}</label>
        <select id="request-lifetime" bind:value={requestLifetime}>
          <option value={3600}>{t.life1h}</option>
          <option value={86400}>{t.life1d}</option>
          <option value={604800}>{t.life7d}</option>
        </select>
      </div>
      <div>
        <label for="expected-sender">{t.expectedSenderLabel}</label>
        <input id="expected-sender" bind:value={expectedCode} placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false" data-testid="expected-sender" />
        <p class="muted small">{t.expectedSenderHint}</p>
      </div>
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="create-request">{t.createRequest}</button>
    </form>
  {/if}
</section>

<style>
  .tabs {
    display: flex;
    gap: var(--s3);
    border-bottom: 1px solid var(--line);
    padding-bottom: var(--s3);
  }

  .tabs button {
    background: none;
    color: var(--muted);
    padding: var(--s3) var(--s4);
  }

  .tabs button.active {
    color: var(--text);
    background: var(--raised);
    border-color: var(--line);
  }
</style>
