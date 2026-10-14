# eslint-plugin-security — ESLint-based JS/TS security linting

Heuristic sink detector for JavaScript/TypeScript. Complements njsscan: it
flags every *usage* of a dangerous API shape with no dataflow analysis, so
recall is high and precision is low. Use it to generate leads over code
njsscan skipped (JSX/TSX, TypeScript, files semgrep failed to parse), then
verify each hit manually or via `taint-analysis`.

## Install

```sh
npm install --save-dev eslint eslint-plugin-security
# TypeScript projects:
npm install --save-dev typescript-eslint
# SARIF export:
npm install --save-dev @microsoft/eslint-formatter-sarif
```

## Flat config (ESLint ≥ 9) — `eslint.config.mjs`

```js
import pluginSecurity from "eslint-plugin-security";

export default [
  pluginSecurity.configs.recommended,   // enables all detect-* rules as warn
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: {
      // promote the high-signal ones for a security pass
      "security/detect-child-process": "error",
      "security/detect-eval-with-expression": "error",
      "security/detect-unsafe-regex": "error",
    },
  },
];
```

TypeScript-aware config:

```js
import pluginSecurity from "eslint-plugin-security";
import tseslint from "typescript-eslint";

export default tseslint.config(
  ...tseslint.configs.recommended,
  pluginSecurity.configs.recommended,
  { files: ["**/*.ts", "**/*.tsx"] },
);
```

Legacy `.eslintrc` (ESLint ≤ 8):

```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended-legacy"]
}
```

## Run with SARIF output

```sh
npx eslint . \
  --no-eslintrc --config eslint.config.mjs \
  -f @microsoft/eslint-formatter-sarif \
  -o eslint.sarif
# eslint exits 1 when any error-level rule fires; that still means "scan OK"
```

The SARIF lands in the same pipeline as njsscan's:
`python3 scripts/njsscan_to_workunits.py eslint.sarif -o eslint-wu.json`
(the parser handles any SARIF 2.1.0), then route it to the `sarif-triage`
skill together with `njsscan.sarif` for dedup.

Quick scan without touching the repo's own ESLint setup: write a throwaway
`eslint.config.mjs` as above in a temp dir and point ESLint at the source
with positional paths; use `--no-config-lookup` (ESLint 9) to stop it from
picking up the project config.

## Rule list (all `security/` prefixed)

| Rule | Fires on | Signal |
|---|---|---|
| `detect-child-process` | `require("child_process")`, `exec()` calls | High — review every hit for tainted args |
| `detect-eval-with-expression` | `eval(expr)` where expr is not a literal | High |
| `detect-non-literal-require` | `require(variable)` | Medium — dynamic module load = code injection vector |
| `detect-non-literal-fs-filename` | `fs.*` with non-literal path args | Medium — path traversal leads; very noisy in file-heavy code |
| `detect-non-literal-regexp` | `new RegExp(variable)` | Medium — ReDoS / regex injection |
| `detect-unsafe-regex` | regex literals with catastrophic backtracking (safe-regex) | High for ReDoS |
| `detect-object-injection` | `obj[variable]` member access | Very noisy — only interesting when the key comes from a request (prototype pollution reads/writes) |
| `detect-possible-timing-attacks` | `==`/`===` comparisons against names like password/secret/token | Medium |
| `detect-pseudoRandomBytes` | `crypto.pseudoRandomBytes` | High |
| `detect-buffer-noassert` | `Buffer` read/write with `noAssert: true` | Low (legacy) |
| `detect-new-buffer` | `new Buffer(...)` (uninitialized memory) | Medium (legacy Node) |
| `detect-disable-mustache-escape` | `object.escapeMarkup = false` | High — stored XSS |
| `detect-no-csrf-before-method-override` | `csrf` middleware ordered after `method-override` | High for Express |
| `detect-bidi-characters` | Unicode bidi control chars (trojan-source) | High when present |
| `detect-eval-with-string` *(where available)* / string-arg timers | string `setTimeout`/`setInterval` | High |

## Why it is noisy — triage strategy

The plugin matches AST shapes only: `detect-object-injection` fires on every
computed member access, `detect-non-literal-fs-filename` on every dynamic
path. Expect hundreds of warnings on a mid-size app. Strategy:

1. Sort by rule: start with `detect-child-process`,
   `detect-eval-with-expression`, `detect-non-literal-require`,
   `detect-unsafe-regex`, `detect-disable-mustache-escape`.
2. For each hit, answer one question: *can request/network/file data reach
   this expression?* If plausible, hand the source→sink trace to the
   `taint-analysis` skill (JavaScript sinks) or write a targeted semgrep
   taint rule.
3. `detect-object-injection` is only worth bulk review in request handlers
   and deep-merge/options-parsing code (prototype pollution candidates).
4. Treat it as lead generation: never file a finding straight from an
   eslint-plugin-security warning without a verified path.
