<script lang="ts">
  import { t } from '../lib/i18n';
  import type { Retention } from '../lib/relay';

  let {
    retention = $bindable<Retention>('burn_after_reading'),
    lifetime = $bindable(86400),
    passphrase = $bindable(''),
  }: { retention?: Retention; lifetime?: number; passphrase?: string } = $props();

  let withPassphrase = $state(false);
  const lifetimes = [
    { seconds: 300, label: t.life5m },
    { seconds: 3600, label: t.life1h },
    { seconds: 86400, label: t.life1d },
    { seconds: 604800, label: t.life7d },
  ];

  $effect(() => {
    if (!withPassphrase) passphrase = '';
  });
</script>

<fieldset>
  <legend>{t.whenDestroy}</legend>
  <label class="choice">
    <input type="radio" bind:group={retention} value="burn_after_reading" data-testid="retention-burn" />
    <span><strong>{t.burn}</strong><br /><span class="muted small">{t.burnHint}</span></span>
  </label>
  <label class="choice">
    <input type="radio" bind:group={retention} value="until_expiry" data-testid="retention-expiry" />
    <span><strong>{t.expiry}</strong><br /><span class="muted small">{t.expiryHint}</span></span>
  </label>
</fieldset>

<div>
  <label for="lifetime">{t.lifetime}</label>
  <select id="lifetime" bind:value={lifetime} data-testid="lifetime">
    {#each lifetimes as option (option.seconds)}
      <option value={option.seconds}>{option.label}</option>
    {/each}
  </select>
</div>

<div>
  <label class="choice">
    <input type="checkbox" bind:checked={withPassphrase} data-testid="with-passphrase" />
    <span>{t.addPassphrase}</span>
  </label>
  {#if withPassphrase}
    <input type="password" autocomplete="new-password" aria-label={t.passphrase} bind:value={passphrase} data-testid="passphrase" />
    <p class="muted small hint">{t.passphraseHint}</p>
  {/if}
</div>

<style>
  /* Only the sides and bottom: the top margin is the stack's rhythm. */
  fieldset {
    border: 0;
    padding: 0;
    margin-inline: 0;
    margin-bottom: 0;
  }

  legend {
    font-weight: 600;
    margin-bottom: var(--s3);
  }

  .choice {
    display: flex;
    gap: var(--s4);
    align-items: flex-start;
    font-weight: 400;
    margin-bottom: var(--s3);
  }

  .choice input {
    width: auto;
    margin-top: var(--s2);
    accent-color: var(--wax);
  }

  .hint {
    margin-top: var(--s3);
  }
</style>
