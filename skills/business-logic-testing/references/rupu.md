# rupu wiring for business-logic-testing

Every parse/handoff step in this skill ends in one of three rupu-ingestible
outputs: a **work-units JSON array**, **`assets.mark`** calls, or a
**`findings.report`** call. This file gives the exact shapes.

Shared skills referenced by name (same rupu-skills library — use them, do not
reimplement): **`work-units`** (canonical work-unit splitter/normalizer),
**`coverage-assets`** (asset recording conventions), **`finding-report`**
(writing a complete finding).

---

## 1. Work units (fan-out over workflows × attacks)

`scripts/workunits_from_workflows.py workflows.json --work-units busl-units.json`
writes a clean JSON **array** whose first character is `[` — rupu's
`for_each:` JSON-parses such a file (read via the `read_file` tool), and a
lead agent can read the same file and `dispatch` one child per element. Hand
the array to the `work-units` skill for normalization/merging with other
packs' units.

Element shape:

```json
[
  {
    "id": "checkout-busl-04-race",
    "title": "Race the coupon redemption in workflow 'checkout'",
    "targets": ["https://example.com/api/coupon/redeem"],
    "hints": {
      "skill": "business-logic-testing",
      "wstg": "WSTG-BUSL-04",
      "workflow": "checkout",
      "attack": "parallel-request race: N simultaneous redemptions, confirm duplicated effect server-side",
      "steps": "POST /cart/add -> POST /api/coupon/redeem -> POST /checkout/complete",
      "notes": "coupon SAVE10 is single-use per account"
    }
  }
]
```

Handoffs to other skills (upload routes → `file-upload-testing`, cross-user
tampering → authorization testing) are emitted the same way: one unit each,
`hints.skill` naming the target skill.

## 2. Assets (coverage)

Use the rupu `assets.mark` tool with the built-in `web` profile kinds
(profile-namespaced — prefix `web:`). Depth ladder:
`mapped` → `crawled` → `tested` → `exploited`; mark the rung actually reached.

Site, when you start mapping it:

```json
{"kind": "web:site",
 "coordinates": [{"t": "url", "v": "https://example.com"}],
 "label": "https://example.com",
 "depth": "mapped"}
```

Workflow step captured during the legitimate walkthrough:

```json
{"kind": "web:route",
 "coordinates": [{"t": "url", "v": "https://example.com"},
                 {"t": "http_route", "v": "/api/coupon/redeem"},
                 {"t": "param", "v": "code"}],
 "label": "POST /api/coupon/redeem (checkout step 2)",
 "depth": "crawled"}
```

After running BUSL cases against it → same call, `"depth": "tested"`.
After a confirmed abuse → `"depth": "exploited"`.
Mark *every* step of *every* workflow, including those that checked clean —
that is what makes BUSL coverage auditable. Conventions: `coverage-assets`
skill.

## 3. Findings

Record each verified abuse with `findings.report` via the `finding-report`
skill. Web profile completeness checks require all three of: finding pinned
to a route/url, an HTTP exchange in evidence, and an OWASP-or-CWE
classification. Use scope `endpoint` with `target_ref` = the affected URL
(scope `host` only for host-wide issues). Severity ∈
info|low|medium|high|critical, set by business impact.

```json
{
  "title": "Race condition in coupon redemption allows unlimited reuse of single-use coupon",
  "scope": "endpoint",
  "target_ref": "https://example.com/api/coupon/redeem",
  "severity": "high",
  "classification": {"wstg": "WSTG-BUSL-04", "cwe": "CWE-367"},
  "evidence": {
    "rationale": "The redeem endpoint checks coupon state before marking it used without atomicity. 20 synchronized identical requests (last-byte sync) yielded 7 responses with {\"applied\":true}; the account's order afterwards shows the discount applied 7 times (state check: GET /api/cart -> discount_total 70.00 vs expected 10.00). One redemption should succeed per coupon.",
    "http_exchange": "POST /api/coupon/redeem HTTP/1.1\r\nHost: example.com\r\nCookie: session=...\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"code\":\"SAVE10\"}\n\n--- response (x7 identical) ---\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"applied\":true,\"discount\":10.00}",
    "reproduction": "python3 scripts/race_runner.py --request-file redeem.req --force-ssl --concurrency 20 --sync last-byte --warm --success-regex '\"applied\":true'",
    "artifacts": ["race-result.json"]
  }
}
```

Classification quick map for this skill:
- BUSL-01 data validation → CWE-20 / CWE-602 (client-side enforcement)
- BUSL-02 forged requests → CWE-840 / CWE-650
- BUSL-03 integrity → CWE-915 (mass assignment) / CWE-345
- BUSL-04 races → CWE-367 (TOCTOU) / CWE-362
- BUSL-05 limits → CWE-837
- BUSL-06 workflow → CWE-841
- BUSL-07 misuse defenses → CWE-778 / CWE-799

`scripts/race_runner.py --finding-out finding.json` emits a draft of exactly
this shape for confirmed races — add the server-side state check to the
rationale and adjust severity before submitting.

## 4. Step-by-step wiring summary

| Methodology step                      | rupu output |
|---------------------------------------|-------------|
| Phase 1 workflow mapping              | `assets.mark` site `mapped`, routes `crawled`; `workunits_from_workflows.py --work-units` → `work-units` skill |
| Phase 2 each BUSL case executed       | `assets.mark` route `tested` (or `exploited`); confirmed abuse → `findings.report` via `finding-report` |
| Phase 2 BUSL-08/09 upload routes      | work unit with `hints.skill: file-upload-testing` |
| Phase 3 race run parsed               | `race-result.json` reviewed → on win `finding.json` → `findings.report`; route depth `exploited` |
| Phase 4 handoffs (ATHZ, crypto, etc.) | work units naming the target skill |
