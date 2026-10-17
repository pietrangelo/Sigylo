<script lang="ts">
  import { engine, errorCode, loadEngine, passphraseBytes, randomBytes, textBytes } from '../lib/crypto';
  import { t } from '../lib/i18n';
  import { inboxLink, requestLink, revokeLink, secretLink } from '../lib/links';
  import { formatExpiry, relayMessage, sealMessage } from '../lib/messages';
  import { Relay, type Retention } from '../lib/relay';
  import { linkOrigin, relayFetch } from '../lib/platform';
  import LinkBox from './LinkBox.svelte';
  import SealOptions from './SealOptions.svelte';

  const relay = new Relay(relayFetch);
  let tab: 'send' | 'receive' = $state('send');
  let secret = $state('');
  let retention: Retention = $state('burn_after_reading');
  let lifetime = $state(86400);
  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let sent: { link: string; revoke: string; expires: number } | null = $state(null);
  let requested: { request: string; inbox: string; expires: number } | null = $state(null);
  let expectedCode = $state('');

  async function seal(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await loadEngine();
      const pass = passphraseBytes(passphrase);
      const sealed = engine.sealForLink(textBytes(secret), pass);
      const key = sealed.key;
      const envelope = sealed.envelope;
      sealed.free();
      const token = randomBytes(32);
      const result = await relay.deposit(envelope, retention, lifetime, token);
      if (!result.ok) {
        error = relayMessage(result.error);
        return;
      }
      sent = {
        link: secretLink(linkOrigin, result.value.id, key, pass !== undefined),
        revoke: revokeLink(linkOrigin, result.value.id, token),
        expires: result.value.expiresAt,
      };
      secret = '';
      passphrase = '';
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
    }
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
      <button class="secondary" onclick={reset}>{t.another}</button>
    </div>
  {:else if tab === 'send'}
    <form class="stack" onsubmit={seal}>
      <div>
        <label for="secret">{t.secretLabel}</label>
        <textarea id="secret" bind:value={secret} placeholder={t.secretPlaceholder} autocomplete="off" spellcheck="false" required data-testid="secret"></textarea>
      </div>
      <SealOptions bind:retention bind:lifetime bind:passphrase />
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="seal">{busy ? t.sealing : t.seal}</button>
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
