import { test as base } from '@playwright/test';

let client = 0;

// Every test is its own client for the relay's per-address limiter, so the
// suite can grow past one minute's allowance. wrangler dev takes the address
// from CF-Connecting-IP; in production Cloudflare sets it and ignores ours.
export const test = base.extend({
  extraHTTPHeaders: async ({ extraHTTPHeaders }, use) => {
    client += 1;
    await use({ ...extraHTTPHeaders, 'CF-Connecting-IP': `10.${process.pid % 256}.${client >> 8}.${client & 255}` });
  },
});

export { expect } from '@playwright/test';
