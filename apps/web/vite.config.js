import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  define: {
    global: "globalThis",
  },
  server: {
    port: 6767,
    proxy: {
      "/auth": "http://localhost:4400",
      "/keys": "http://localhost:4400",
      "/profile": "http://localhost:4400",
      "/messages": "http://localhost:4400",
    },
  },
});
