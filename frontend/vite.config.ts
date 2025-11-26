import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig(async ({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const base = env.VITE_BASE_URL || "/";
  const plugins = [react()];
  if (mode === "development") {
    try {
      const mod = await import("lovable-tagger");
      if (mod?.componentTagger) plugins.push(mod.componentTagger());
    } catch {}
  }
  return {
    base,
    server: {
      host: "::",
      port: 8080,
      allowedHosts: ["localhost", "127.0.0.1", "7114a8347d47.ngrok-free.app"],
      hmr: false,
      proxy: {
        "/api": {
          target: "http://localhost:3001",
          changeOrigin: true,
          secure: false,
        },
        "/uploads": {
          target: "http://localhost:3001",
          changeOrigin: true,
          secure: false,
        },
      },
    },
    plugins,
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
  };
});
