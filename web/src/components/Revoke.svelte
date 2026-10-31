<script lang="ts">
  import { t } from '../lib/i18n';
  import { dropKeyFromAddress } from '../lib/links';
  import { relayMessage } from '../lib/messages';
  import { Relay } from '../lib/relay';
  import { relayFetch } from '../lib/platform';

  let { id, token }: { id: Uint8Array; token: Uint8Array } = $props();

  const relay = new Relay(relayFetch);
  let busy = $state(false);
  let error = $state('');
  let done = $state(false);

  async function revoke() {
    busy = true;
    error = '';
    const result = await relay.revoke(id, token);
    busy = false;
    if (result.ok) {
      // The token has done its job: drop it from the address bar and history entry.
      dropKeyFromAddress();
      done = true;
    } else {
      error = relayMessage(result.error);
    }
  }
</script>

<section class="card stack">
  <h2>{t.revokeTitle}</h2>
  {#if done}
    <p class="success" data-testid="revoked">{t.revoked}</p>
  {:else}
    <p class="muted">{t.revokeIntro}</p>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <button class="primary" onclick={revoke} disabled={busy} data-testid="revoke">{t.revoke}</button>
  {/if}
</section>
