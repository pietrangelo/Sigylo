<script lang="ts">
  // Opens a secret from a link (link mode) or from the recipient's private
  // inbox link (request mode). The envelope is fetched with one POST, which
  // may burn it, so it stays in memory: a mistyped passphrase can be retried
  // without asking the relay again. A file's chunks are kept as they arrive
  // for the same reason: a burning chunk comes only once.
  import { bytesText, engine, errorCode, loadEngine, passphraseBytes } from '../lib/crypto';
  import { downloadChunks, saveFile } from '../lib/files';
  import { t } from '../lib/i18n';
  import { formatSize, relayMessage, sealMessage } from '../lib/messages';
  import { Relay, type Opened } from '../lib/relay';
  import { relayFetch } from '../lib/platform';

  let {
    mode,
    id,
    secret,
    expectsPassphrase,
  }: { mode: 'link' | 'inbox'; id: Uint8Array; secret: Uint8Array; expectsPassphrase: boolean } = $props();

  const relay = new Relay(relayFetch);
  let opened: Opened | null = null;
  const chunks: Uint8Array[] = [];
  let burned = $state(false);
  let askedForPassphrase = $state(false);
  const needsPassphrase = $derived(expectsPassphrase || askedForPassphrase);
  let passphrase = $state('');
  let busy = $state(false);
  let downloading = $state(false);
  let error = $state('');
  let plaintext: string | null = $state(null);
  let file: { name: string; size: number; contents: Uint8Array } | null = $state(null);
  let visible = $state(true);

  /** The file a manifest stands for, once every chunk is in. */
  async function openFile(manifest: Uint8Array): Promise<boolean> {
    const info = engine.fileInfo(manifest);
    if (info === undefined) return false;
    const { name, size } = info;
    const expected = info.chunks;
    info.free();
    // The relay's count is only a hint; the sealed manifest decides.
    if (opened?.chunks !== expected) throw new Error('NotAuthentic');
    downloading = true;
    const result = await downloadChunks(relay, id, expected, opened.claim, chunks);
    if (!result.ok) {
      error = result.error === 'NotFound' ? t.errFileIncomplete : relayMessage(result.error);
      return true;
    }
    file = { name, size, contents: engine.openFile(manifest, result.value) };
    chunks.length = 0;
    return true;
  }

  async function open(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await loadEngine();
      if (opened === null) {
        const result = await relay.open(id);
        if (!result.ok) {
          error = result.error === 'NotFound' && mode === 'inbox' ? t.inboxEmpty : relayMessage(result.error);
          return;
        }
        opened = result.value;
        burned = result.value.burned;
        if (engine.envelopeNeedsPassphrase(opened.envelope) && passphrase === '') {
          askedForPassphrase = true;
          return;
        }
      }
      const pass = passphraseBytes(passphrase);
      const envelope = opened.envelope;
      const bytes = mode === 'link' ? engine.openLink(envelope, secret, pass) : engine.openAsRecipient(envelope, secret, pass);
      try {
        const isFile = await openFile(bytes);
        if (!isFile) plaintext = bytesText(bytes);
      } finally {
        bytes.fill(0);
      }
      if (plaintext === null && file === null) return;
      opened = null;
      // The key has done its job: drop it from the address bar and history entry.
      history.replaceState(null, '', location.pathname);
    } catch (e) {
      error = sealMessage(errorCode(e));
    } finally {
      busy = false;
      downloading = false;
    }
  }

  async function copy() {
    if (plaintext !== null) await navigator.clipboard.writeText(plaintext);
  }
</script>

<section class="card stack">
  {#if file !== null}
    <h2>{mode === 'inbox' ? t.inboxTitle : t.revealTitle}</h2>
    <p class={burned ? 'notice' : 'success'} data-testid="retention-note">{burned ? t.burnedFile : t.readableUntil}</p>
    <p class="file"><strong data-testid="file-name">{file.name}</strong> <span class="muted">{formatSize(file.size)}</span></p>
    <button class="primary" onclick={() => file && saveFile(file.name, file.contents)} data-testid="save-file">{t.saveFile}</button>
  {:else if plaintext !== null}
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
      <button class="primary" type="submit" disabled={busy} data-testid="reveal">{downloading ? t.downloading : busy ? t.opening : error ? t.retry : t.reveal}</button>
    </form>
  {/if}
</section>

<style>
  .row {
    display: flex;
    gap: var(--s3);
  }

  .file {
    overflow-wrap: anywhere;
  }
</style>
