import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export function makeViteConfig(appName: string) {
  return defineConfig({
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: appName === "server-admin" ? 4173 : 4174
    }
  });
}
