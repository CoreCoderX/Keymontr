// @ts-check

import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      "regex/assets/**",
      "stringgroup/assets/**",
      "*.min.js"
    ]
  },

  {
    files: [
      "**/*.ts"
    ],

    extends: [
      js.configs.recommended,
      tseslint.configs.recommendedTypeChecked
    ],

    languageOptions: {
      parser: tseslint.parser,

      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    },

    rules: {
      /*
       * TypeScript safety
       */

      "@typescript-eslint/no-explicit-any": "error",

      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          "argsIgnorePattern": "^_",
          "varsIgnorePattern": "^_",
          "caughtErrorsIgnorePattern": "^_"
        }
      ],

      "@typescript-eslint/no-floating-promises": "error",

      "@typescript-eslint/no-misused-promises": [
        "error",
        {
          "checksVoidReturn": true
        }
      ],

      "@typescript-eslint/await-thenable": "error",

      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",

      "@typescript-eslint/prefer-nullish-coalescing": "error",
      "@typescript-eslint/prefer-optional-chain": "error",

      "@typescript-eslint/strict-boolean-expressions": "error",

      /*
       * General JavaScript/TypeScript correctness
       */

      "eqeqeq": [
        "error",
        "always"
      ],

      "prefer-const": "error",

      "no-var": "error",

      "no-console": [
        "warn",
        {
          "allow": [
            "warn",
            "error"
          ]
        }
      ]
    }
  },

  /*
   * JavaScript configuration/build files.
   *
   * These are Node-side tooling files, not extension source.
   * Do not apply TypeScript type-aware rules to them.
   */
  {
    files: [
      "*.js",
      "*.mjs",
      "*.cjs"
    ],

    extends: [
      tseslint.configs.disableTypeChecked
    ],

    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly",
        require: "readonly",
        module: "readonly",
        __dirname: "readonly"
      }
    }
  },

  /*
   * Tests and the Jest config.
   *
   * Tests are intentionally a little less restrictive about
   * unused variables because fixtures, mocks, and setup helpers
   * can legitimately contain unused values.
   *
   * These files are type-checked under tsconfig.test.json (not the
   * main tsconfig.json used by the project service), so type-aware
   * rules are disabled here to avoid false positives.
   */
  {
    files: [
      "tests/**/*.ts"
    ],

    extends: [
      tseslint.configs.disableTypeChecked
    ],

    languageOptions: {
      parserOptions: {
        project: false,
        projectService: false
      }
    },

    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          "argsIgnorePattern": "^_",
          "varsIgnorePattern": "^_",
          "caughtErrorsIgnorePattern": "^_"
        }
      ],

      /*
       * Benchmark tests deliberately print their results to stdout.
       */
      "no-console": "off"
    }
  }
);
