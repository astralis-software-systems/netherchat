// The `go vet` of the web client: correctness only, no style.
//
// The split is deliberate and mirrors the Go side. There, gofmt owns formatting and
// go vet owns correctness, and they are separate tools run as separate CI steps.
// Here there is no gofmt — JavaScript has no equivalent consensus and a formatter is
// its own decision — so this file owns correctness alone. Nothing below has an
// opinion about quotes, semicolons, or import order, and typescript-eslint's
// `stylistic` tier is deliberately NOT enabled.
//
// Four things earn their place, in the order they matter. Rules the compiler already
// enforces are left to the compiler (tsconfig.app.json is `strict` with
// noUnusedLocals, noUnusedParameters, and noFallthroughCasesInSwitch):
//
//   1. The HTML sinks. This is the rule this file exists for. The join client
//      renders strings an attacker controls — message bodies and display names, both
//      arriving off the wire from any room member — and routes every one of them
//      through textContent. That property is load-bearing and nothing enforced it.
//      It is the browser-side analogue of TestServerBinaryDoesNotLinkClientCrypto:
//      a documented claim promoted to something the build checks.
//   2. Floating promises. Needs type information, which is why the type-checked
//      preset is used below. A swallowed rejection in a crypto or fetch path fails
//      silently, and silent is the worst way for this client to fail.
//   3. `any`. `strict` gives noImplicitAny, which catches *inferred* any and nothing
//      else — an explicit `: any` annotation and the any handed back by JSON.parse
//      both slip past it. The no-unsafe-* family in the preset covers the second.
//   4. Unused bindings. Mostly the compiler's job already. Kept for the two cases it
//      misses: scripts/interop-check.ts, which no tsconfig includes and so tsc never
//      checks at all, and unused catch bindings (caughtErrors below).

import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

// Every hit on the rules below gets this appended, because a bare "not allowed" tells
// the next person nothing about what to do instead.
const SINK_ADVICE =
  "Build the nodes and set textContent instead. If the markup is genuinely static " +
  "with no interpolated data, disable this rule on the line and say why.";

const HTML_SINKS = [
  {
    // `x.innerHTML = …`, `x.outerHTML = …`, and their `+=` forms.
    selector: "AssignmentExpression[left.property.name=/^(inner|outer)HTML$/]",
    message: `innerHTML/outerHTML parses its input as markup. ${SINK_ADVICE}`,
  },
  {
    // The same sink under other names. setHTMLUnsafe is the modern spelling of
    // innerHTML and would otherwise be a one-word way around the rule above.
    selector: "CallExpression[callee.property.name=/^(insertAdjacentHTML|setHTMLUnsafe)$/]",
    message: `insertAdjacentHTML/setHTMLUnsafe parses its input as markup. ${SINK_ADVICE}`,
  },
];

export default tseslint.config(
  { ignores: ["dist/**", "coverage/**"] },

  js.configs.recommended,

  // Type-aware, so no-floating-promises and the no-unsafe-* family actually work.
  // `recommendedTypeChecked` rather than `strictTypeChecked`: the recommended tier is
  // correctness, the strict tier adds preference (prefer-nullish-coalescing and
  // friends), and preference is what this file is trying not to import.
  ...tseslint.configs.recommendedTypeChecked,

  {
    languageOptions: {
      parserOptions: {
        // scripts/*.ts sits outside both tsconfigs (app includes src, node includes
        // vite.config.ts), so allowDefaultProject is what brings the interop check
        // under the linter without editing a tsconfig and changing what tsc builds.
        projectService: { allowDefaultProject: ["scripts/*.ts"] },
        tsconfigRootDir: import.meta.dirname,
      },
      globals: globals.browser,
    },
    rules: {
      "no-restricted-syntax": ["error", ...HTML_SINKS],

      // document.write is the same sink again, reached through a call on a global
      // rather than a property assignment, so the selectors above do not see it.
      "no-restricted-properties": [
        "error",
        {
          object: "document",
          property: "write",
          message: `document.write parses its input as markup. ${SINK_ADVICE}`,
        },
        {
          object: "document",
          property: "writeln",
          message: `document.writeln parses its input as markup. ${SINK_ADVICE}`,
        },
      ],

      // eval is not in eslint:recommended. no-implied-eval (setTimeout("…"), the
      // Function constructor) comes from the type-checked preset above.
      "no-eval": "error",

      // Adds the one thing tsc's noUnusedLocals/noUnusedParameters does not report:
      // a caught error that is never read. `catch (e) { … }` that ignores e is
      // usually a swallowed failure; `catch { … }` says the same thing on purpose.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { caughtErrors: "all", argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },

  // Node, not the browser: the interop vector runner and the Vite config.
  {
    files: ["scripts/**/*.ts", "vite.config.ts"],
    languageOptions: { globals: globals.node },
  },

  // This file itself. It is plain JS in no tsconfig, so the type-aware rules cannot
  // run on it and would otherwise fail the whole lint with a parse error. It stays
  // linted by everything that does not need a type checker.
  {
    files: ["**/*.js"],
    extends: [tseslint.configs.disableTypeChecked],
  },

  // The marketing page, exempted from the sink rules ONLY.
  //
  // src/landing/ builds its theme picker and theme strip from THEMES, a compile-time
  // constant in src/theme/themes.ts — no wire data, no user input, nothing an
  // attacker reaches. That is a different situation from the join client, where every
  // rendered string arrives from the room, and the two should not share a policy by
  // accident. Everything else in this file still applies here; only the sink rules
  // and the async-listener check are off. Revisit if the landing page ever renders
  // anything it did not compile in.
  {
    files: ["src/landing/**/*.ts"],
    rules: {
      "no-restricted-syntax": "off",
      "@typescript-eslint/no-misused-promises": "off",
    },
  },
);
