<script lang="ts">
  // Opens a secret from a link (link mode) or from the recipient's private
  // inbox link (request mode). The envelope is fetched with one POST, which
  // may burn it, so it stays in memory: a mistyped passphrase can be retried
  // without asking the relay again.
  import { bytesText, engine, errorCode, loadEngine, passphraseBytes } from '../lib/crypto';
  import { t } from '../lib/i18n';
  import { relayMessage, sealMessage } from '../lib/messages';
  import { Relay } from '../lib/relay';
  import { relayFetch } from '../lib/platform';

  let {
    mode,
    id,
    secret,
    expectsPassphrase,
  }: { mode: 'link' | 'inbox'; id: Uint8Array; secret: Uint8Array; expectsPassphrase: boolean } = $props();

  const relay = new Relay(relayFetch);
  let envelope: Uint8Array | null = null;
  let burned = $state(false);
  let askedForPassphrase = $state(false);
  const needsPassphrase = $derived(expectsPassphrase || askedForPassphrase);
  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let plaintext: string | null = $state(null);
  let visible = $state(true);

  async function open(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await loadEngine();
      if (envelope === null) {
        const result = await relay.open(id);
        if (!result.ok) {
          error = result.error === 'NotFound' && mode === 'inbox' ? t.inboxEmpty : relayMessage(result.error);
          return;
        }
        envelope = result.value.envelope;
        burned = result.value.burned;
        if (engine.envelopeNeedsPassphrase(envelope) && passphrase === '') {
          askedForPassphrase = true;
          return;
        }
      }
      const pass = passphraseBytes(passphrase);
      const bytes = mode === 'link' ? engine.openLink(envelope, secret, pass) : engine.openAsRecipient(envelope, secret, pass);
      plaintext = bytesText(bytes);
      bytes.fill(0);
      envelope = null;
      // The key has done its job: drop it from the address bar and history entry.
      history.replaceState(null, '', location.pathname);
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
    }
  }

  async function copy() {
    if (plaintext !== null) await navigator.clipboard.writeText(plaintext);
  }
</script>

<section class="card stack">
  {#if plaintext !== null}
    <h2>{mode === 'inbox' ? t.inboxTitle : t.revealTitle}</h2>
    <p class={burned ? 'notice' : 'success'} data-testid="retention-note">{burned ? t.burned : t.readableUntil}</p>
    {#if visible}
      <textarea readonly data-testid="plaintext" value={plaintext}></textarea>
    {:else}
      <p class="muted">••••••••</p>
    {/if}
    <div class="row">
      <button class="primary" onclick={copy}>{t.copy}</button>
      <button class="secondary" onclick={() => (visible = !visible)}>{visible ? t.hide : t.show}</button>
    </div>
  {:else}
    <h2>{mode === 'inbox' ? t.inboxTitle : t.revealTitle}</h2>
    <p class="muted">{t.revealIntro}</p>
    <form class="stack" onsubmit={open}>
      {#if needsPassphrase}
        <div>
          <label for="open-passphrase">{t.needPassphrase}</label>
          <input id="open-passphrase" type="password" autocomplete="off" bind:value={passphrase} required data-testid="open-passphrase" />
        </div>
      {/if}
      {#if error}<p class="error" role="alert" data-testid="open-error">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="reveal">{busy ? t.opening : error ? t.retry : t.reveal}</button>
    </form>
  {/if}
</section>

<style>
  .row {
    display: flex;
    gap: var(--s3);
  }
</style>
