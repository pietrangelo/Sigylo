<script lang="ts">
  // What is being sealed: a text typed here, or a file from the device.
  import { t } from '../lib/i18n';

  let {
    kind = $bindable<'text' | 'file'>('text'),
    text = $bindable(''),
    file = $bindable<File | null>(null),
    id,
  }: { kind?: 'text' | 'file'; text?: string; file?: File | null; id: string } = $props();

  function pick(event: Event) {
    file = (event.currentTarget as HTMLInputElement).files?.[0] ?? null;
  }
</script>

<div class="kinds" role="radiogroup" aria-label={t.secretLabel}>
  <label class:active={kind === 'text'}>
    <input type="radio" bind:group={kind} value="text" data-testid="kind-text" />
    {t.kindText}
  </label>
  <label class:active={kind === 'file'}>
    <input type="radio" bind:group={kind} value="file" data-testid="kind-file" />
    {t.kindFile}
  </label>
</div>

{#if kind === 'text'}
  <div>
    <label for={id}>{t.secretLabel}</label>
    <textarea {id} bind:value={text} placeholder={t.secretPlaceholder} autocomplete="off" spellcheck="false" required data-testid="secret"></textarea>
  </div>
{:else}
  <div>
    <label for="{id}-file">{t.fileLabel}</label>
    <input id="{id}-file" type="file" onchange={pick} required data-testid="file" />
    <p class="muted small hint">{t.fileHint}</p>
  </div>
{/if}

<style>
  .kinds {
    display: flex;
    gap: var(--s3);
  }

  .kinds label {
    display: inline-flex;
    gap: var(--s3);
    align-items: center;
    font-weight: 400;
    margin: 0;
    padding: var(--s2) var(--s4);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    cursor: pointer;
  }

  .kinds label.active {
    background: var(--raised);
    font-weight: 600;
  }

  .kinds input {
    width: auto;
    margin: 0;
    accent-color: var(--wax);
  }

  .hint {
    margin-top: var(--s3);
  }
</style>
