import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  root: ".",
  build: {
    outDir: "dist/client",
    emptyOutDir: true,
    rollupOptions: {
      input: "src/client/main.tsx",
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "chunk-[name].js",
        assetFileNames: ({ name }) =>
          name?.endsWith(".css") ? "app.css" : "assets/[name][extname]",
      },
    },
  },
});
