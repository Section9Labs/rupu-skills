# Severity normalization map

Target scale: **critical / high / medium / low / info**. Resolution order in
`normalize_sarif.py`:

1. `security-severity` (CVSS-like 0–10) if present — most precise.
2. SARIF `level` (result, else rule `defaultConfiguration.level`).
3. Tool-native severity string.
4. Default: `medium` (an unlabeled security finding is not "info").

## 1. security-severity (CVSS banding, GitHub-compatible)

| Score | Normalized |
|---|---|
| 9.0 – 10.0 | critical |
| 7.0 – 8.9 | high |
| 4.0 – 6.9 | medium |
| 0.1 – 3.9 | low |
| 0.0 | info |

## 2. SARIF level

| level | Normalized | Rationale |
|---|---|---|
| error | high | tools reserve error for their serious rules |
| warning | medium | |
| note | low | |
| none / absent | info / fall through | |

## 3. Tool-native scales

| Tool | Native | Normalized |
|---|---|---|
| semgrep | ERROR / WARNING / INFO | high / medium / info |
| bandit | HIGH / MEDIUM / LOW (`issue_severity`) | high / medium / low |
| bandit | `issue_confidence` HIGH/MEDIUM/LOW | kept as `tool_confidence` hint, not severity |
| gosec | HIGH / MEDIUM / LOW | high / medium / low |
| gosec | `confidence` HIGH/MEDIUM/LOW | kept as `tool_confidence` hint |
| CodeQL | error / warning / note + security-severity | banding wins; else level map |
| CodeQL `problem.severity` | error / warning / recommendation | high / medium / low |
| njsscan | ERROR / WARNING / INFO | high / medium / info |
| brakeman | confidence High / Medium / Weak | high / medium / low |
| gitleaks | (none — a found secret) | **high**, CWE-798, always |
| trivy | CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN | critical / high / medium / low / low |
| npm audit | critical / high / moderate / low / info | critical / high / medium / low / info |
| pip-audit / osv | CVSS score when present | CVSS banding above |
| generic | blocker / major / minor | critical / high / low |
| generic | important / moderate / informational | high / medium / info |

The full string table is `NATIVE_SEV` in `scripts/normalize_sarif.py`; extend
it there when onboarding a new tool rather than special-casing downstream.

## Priority weights (dedupe_findings.py)

```
priority = W(severity) * (1 + 0.4 * (corroboration - 1))
           + 10 if code_flow present
           + 5  if tool_confidence == high
           * 0.3 if noise path (tests/vendor/generated)

W: critical=100, high=70, medium=40, low=15, info=5
```

Worked examples:

- high, flagged by semgrep + CodeQL, with a code flow:
  `70 * 1.4 + 10 = 108.0` → top of the queue.
- critical, single tool, in `vendor/`: `100 * 0.3 = 30.0` → below a clean
  medium (40.0). Review it, but after production code.
- info, single tool: `5.0`, confidence `low` → likely-noise class.

## Confidence classes

| Condition | confidence |
|---|---|
| noise path OR severity == info | low |
| corroboration ≥ 2 OR code_flow present (and not noise) | high |
| otherwise | medium |

Use confidence to order *verification effort*; use priority to order the
queue. A `low` confidence critical still gets eyes — just not the first pair.
