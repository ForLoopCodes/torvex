import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  define: {
    global: "globalThis",
  },
  resolve: {
    alias: {
      stream: "stream-browserify",
    },
  },
  server: {
    port: 6767,
    proxy: {
      "/auth": "http://localhost:4400",
    },
  },
});
