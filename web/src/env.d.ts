/// <reference types="svelte" />
/// <reference types="vite/client" />

declare module 'virtual:wasm-integrity' {
  const integrity: string;
  export default integrity;
}
