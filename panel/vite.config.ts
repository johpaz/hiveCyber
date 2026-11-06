import { defineConfig } from 'vite';

// Dev server proxies /api (REST + WebSocket) to the local gateway.
const gateway = process.env.HIVECYBER_GATEWAY ?? 'http://127.0.0.1:18791';

export default defineConfig({
  esbuild: { target: 'es2022' },
  server: { proxy: { '/api': { target: gateway, ws: true, changeOrigin: false } } },
});
