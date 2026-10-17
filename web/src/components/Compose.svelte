<script lang="ts">
  import { engine, errorCode, fileName, loadEngine, passphraseBytes, randomBytes, textBytes } from '../lib/crypto';
  import { MAX_FILE_LEN, uploadChunks } from '../lib/files';
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
  let retention: Retention = $state('burn_after_reading');
  let lifetime = $state(86400);
  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let sent: { link: string; revoke: string; expires: number; saved: boolean | null } | null = $state(null);
  let requested: { request: string; inbox: string; expires: number } | null = $state(null);
  let expectedCode = $state('');

  async function seal(event: SubmitEvent) {
    event.preventDefault();
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
      if (chunks !== undefined) {
        uploading = true;
        const uploaded = await uploadChunks(relay, result.value.id, chunks);
        if (!uploaded.ok) {
          // Nobody can open a file with missing chunks; take the manifest back too.
          await relay.revoke(result.value.id, token);
          error = relayMessage(uploaded.error);
          return;
        }
      }
      sent = {
        link: secretLink(linkOrigin, result.value.id, key, pass !== undefined),
        revoke: revokeLink(linkOrigin, result.value.id, token),
        expires: result.value.expiresAt,
        saved: null,
      };
      secret = '';
      file = null;
      passphrase = '';
      await remember(result.value.id, token, result.value.expiresAt);
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
      uploading = false;
    }
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
      const result = await relay.postRequest(publicKey, lifetime);
      if (!result.ok) {
        error = relayMessage(result.error);
        return;
      }
      requested = {
        request: requestLink(linkOrigin, result.value.id, fingerprint, pin),
        inbox: inboxLink(linkOrigin, result.value.id, seed, pin),
        expires: result.value.expiresAt,
      };
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
    }
  }

  function reset() {
    sent = null;
    requested = null;
  }
</script>

<section class="card stack">
  <div class="tabs" role="tablist">
    <button role="tab" aria-selected={tab === 'send'} class:active={tab === 'send'} onclick={() => ((tab = 'send'), reset())}>{t.tabSend}</button>
    <button role="tab" aria-selected={tab === 'receive'} class:active={tab === 'receive'} onclick={() => ((tab = 'receive'), reset())} data-testid="tab-receive">{t.tabReceive}</button>
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
    </div>
  {:else}
    <form class="stack" onsubmit={createRequest}>
      <p>{t.receiveIntro}</p>
      <div>
        <label for="request-lifetime">{t.lifetime}</label>
        <select id="request-lifetime" bind:value={lifetime}>
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
