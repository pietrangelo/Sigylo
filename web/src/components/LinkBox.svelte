<script lang="ts">
  import { t } from '../lib/i18n';

  let { label, value, testid }: { label: string; value: string; testid: string } = $props();
  let copied = $state(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => (copied = false), 1618);
  }
</script>

<div class="box">
  <label for={testid}>{label}</label>
  <div class="row">
    <input id={testid} data-testid={testid} readonly {value} onfocus={(e) => e.currentTarget.select()} />
    <button class="secondary" onclick={copy}>{copied ? t.copied : t.copy}</button>
  </div>
</div>

<style>
  .row {
    display: flex;
    gap: var(--s3);
  }

  input {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: var(--t-small);
  }
</style>
