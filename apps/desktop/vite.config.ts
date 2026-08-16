import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri drives this dev server, so the port is fixed and failure to bind is an
// error rather than something to silently work around.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
});
