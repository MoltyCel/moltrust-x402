import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/hono.ts", "src/express.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  splitting: false,
});
