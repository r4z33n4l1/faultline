import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      "schema/**",
      "test/fixtures/**",
      "bench/seeded-app/**",
      "bench/.cache/**",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
);
