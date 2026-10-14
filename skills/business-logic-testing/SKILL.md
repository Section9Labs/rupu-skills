---
name: business-logic-testing
description: Manual, reasoning-driven testing of application business logic (OWASP WSTG-BUSL) — price/quantity/coupon tampering, forged and replayed requests, integrity bypass, race conditions, limit overruns, and workflow step-skipping. Use after the application is mapped and its multi-step workflows (checkout, transfer, registration, approval, redemption) are understood; produces confirmed logic-abuse findings with the proving request sequence.
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-BUSL-01..09
---

# Business-Logic Testing (WSTG-BUSL)

Business-logic flaws are context-specific: a scanner cannot know that an order
total should never be negative, that a coupon should apply once, or that step 3
must follow step 2. This skill teaches how to *reason* about a workflow, which
concrete tampering/replay/race attacks to try at each point, and how to prove
impact with a reproducible request sequence.

**Input:** a mapped application — routes, parameters, and at least one complete
walkthrough of each workflow (from Burp/ZAP/mitmproxy history or a crawl).
**Output:** `findings.report` calls for each confirmed abuse, `assets.mark`
coverage for every route touched, and work-unit fan-out for parallel testing.
rupu wiring details: `references/rupu.md`.

---

## Phase 1 — Understand the workflow before attacking it

You cannot break logic you have not modeled. For every multi-step process:

1. **Walk it legitimately once** through an intercepting proxy
   (`mitmproxy -w workflow.flows` or Burp Proxy) and record every request in
   order. Replay-friendly capture matters later: `mitmdump -nC workflow.flows`
   replays it; Burp Repeater holds each step.
2. **Draw the state machine.** Name the states (cart → address → payment →
   confirm → complete) and the request that causes each transition. Note which
   state the *server* tracks (session/DB) vs. which the *client* asserts
   (hidden fields, `step=3`, signed-looking tokens, JWT claims).
3. **List every client-supplied value the server should re-derive**: price,
   discount, tax, total, currency, quantity, account id, recipient, role,
   status, `is_admin`, `order_state`, item id vs. price pairing. Each is a
   tampering candidate.
4. **Find the trust boundary.** Anything computed in JavaScript and POSTed back
   is attacker-controlled. Anything in a hidden field, cookie, or
   non-HttpOnly-looking token is attacker-controlled. Decode every opaque blob
   (Base64, JWT, URL-encoded JSON) — "opaque" is not "server-authoritative".
5. **Record the model** as `workflows.json` (shape documented in
   `scripts/workunits_from_workflows.py`) and mark coverage:
   - `assets.mark` kind `web:site` for the app (depth `mapped`),
   - `assets.mark` kind `web:route` for each workflow step you captured
     (depth `crawled`).

**Fan out:** run
`python3 scripts/workunits_from_workflows.py workflows.json --work-units busl-units.json`
to emit one work unit per workflow × BUSL attack pattern, then hand the array
to the `work-units` skill so a lead agent (or a `for_each:` workflow step) can
dispatch one logic-testing child per unit. Exact JSON shape:
`references/rupu.md`.

---

## Phase 2 — The WSTG-BUSL test cases

Full attack detail and payload lists live in `references/wstg-busl-cases.md`.
Run every case against every workflow; the matrix is the methodology.

### WSTG-BUSL-01 — Business-logic data validation
Tamper the business *meaning* of values, not their syntax:
- Quantity: `-1`, `0`, `0.5`, `2147483648`, `9999999999999999`, `1e308`.
  A negative quantity on one line item can discount the whole cart.
- Price/total/discount/tax sent by the client: set price to `0.01`, total to
  `0`, discount to `100`, tax to `-50`. If the server honors any of them, the
  checkout math is client-side — critical.
- Currency and precision: switch `USD`→`IDR` at payment, pay `0.001` where the
  gateway rounds to `0.00`, exploit float rounding (`19.999999`).
- Cross-field consistency: item id of a cheap product with the SKU/price of an
  expensive one; shipping address in one country, tax region in another.

### WSTG-BUSL-02 — Ability to forge requests
Invoke actions the UI never offers:
- Replay a captured request with parameters changed to values the UI never
  presents (`role=admin`, `status=approved`, `plan=enterprise`).
- Guess undocumented siblings of known actions: seen `POST /order/cancel`?
  Try `/order/approve`, `/order/refund`, `/order/complete`. Seen `action=view`?
  Try `action=edit|delete|export|debug`.
- Add parameters the request never had: `&debug=1`, `&admin=true`,
  `&discount=100`, `&test=1`, `&skip_payment=1`.

### WSTG-BUSL-03 — Integrity checks
Attack values that should be server-authoritative:
- Modify balance/role/status fields anywhere they appear in a request —
  profile updates that accept extra JSON keys (mass assignment:
  `{"email":"a@example.com","role":"admin","balance":99999}`).
- Tamper signed-looking tokens: strip the signature, re-sign JWTs with
  `alg:none`, flip Base64-encoded state blobs and see if the server verifies.
- Downgrade/replay old values: resubmit a pre-discount cart token after prices
  changed; reuse a `state` value from a cheaper session.

### WSTG-BUSL-04 — Process timing & race conditions
The classic parallel-request race (TOCTOU / limit overrun): N simultaneous
requests to a check-then-act endpoint — redeem a coupon, withdraw funds, claim
a gift card, apply a one-time promotion, like/vote once, transfer the same
balance twice. If 2+ succeed where 1 should, the window is exploitable.
**This is Phase 3 below** — use `scripts/race_runner.py` or Turbo Intruder.
Also test *timing as an oracle*: does a long-running step (payment callback)
leave the order in a privileged intermediate state you can act from?

### WSTG-BUSL-05 — Function-use limits
Exceed intended counts without concurrency:
- Reuse a one-time coupon by replaying the exact redemption request; by
  re-adding it after removal; by case/whitespace/Unicode variants of the code
  (`SAVE10`, `save10`, `SAVE10 `, `ЅAVE10`).
- Free-trial reuse: new account with `user+2@example.com`, dot-variants,
  reset device/cookie fingerprints.
- One-vote/one-download/one-entry limits: replay, delete-and-redo, parallel
  sessions, API vs. web endpoint for the same action.

### WSTG-BUSL-06 — Workflow circumvention
Skip, reorder, or repeat state transitions:
- Jump straight to the final request: send the `POST /checkout/complete` or
  `GET /order/confirm?order=1234` captured earlier *without* the payment step.
- Reorder: apply the coupon after payment authorization; change the cart after
  the total was locked; change shipping after the price was computed.
- Repeat: run step 2 twice (double-apply a credit); go backward (payment →
  cart edit → confirm) and see which total wins.
- Cross-session/cross-user: complete step 1–2 as user A, step 3 with user B's
  session or B's `order_id` (overlaps WSTG-ATHZ — report both).
- Email/phone verification bypass: hit the post-verification endpoint
  directly; reuse another account's verification link pattern; register,
  change email, keep verified status.

### WSTG-BUSL-07 — Defenses against application misuse
Probe whether the app notices abuse at all: hundreds of failed coupon guesses,
rapid-fire transfers, impossible navigation. No lockout/alert/CAPTCHA on
abuse-sensitive actions is a (low/medium) finding that *amplifies* every other
BUSL finding — note it in their evidence.

### WSTG-BUSL-08 / 09 — Unexpected and malicious file upload
If a workflow accepts files (avatar, invoice, import CSV), hand that route to
the `file-upload-testing` skill; record the handoff as a work unit. Within
*this* skill, still test logic around the upload: import a CSV that sets
`price=0`, upload a review image to someone else's product, re-import to
duplicate credits.

**After each case:** mark the route `assets.mark` depth `tested`; if the abuse
is confirmed, depth `exploited` and report it (Phase 4).

---

## Phase 3 — Race conditions in depth

Full technique (connection warming, last-byte sync, single-packet attack,
Turbo Intruder scripts, detection math): `references/race-conditions.md`.

Quick path with the bundled runner (stdlib only):

```sh
# 20 synchronized identical POSTs, last-byte sync, from a raw request file
python3 scripts/race_runner.py --request-file redeem.req --force-ssl \
    --concurrency 20 --sync last-byte --warm \
    --success-regex '"applied"\s*:\s*true' \
    --output race-result.json --finding-out finding.json

# or inline
python3 scripts/race_runner.py --url https://example.com/api/coupon/redeem \
    --method POST -H 'Content-Type: application/json' \
    -H 'Cookie: session=...' --data '{"code":"SAVE10"}' \
    --concurrency 30 --output race-result.json
```

How it works: K sockets are opened and TLS-handshaked up front, every request
is sent *except its final byte*, all threads block on a barrier, then the last
bytes go out together — the server sees K near-simultaneous completions.
`--warm` first sends a keep-alive `GET /` on each connection so the pool/TLS
caches are hot.

**Detecting a win:** the JSON summary groups responses by
(status, length, body-hash). A race win is **>1 response in the success class**
when exactly one should succeed — or, better, a *state* check afterward:
balance decreased twice, coupon applied twice, two orders exist. Always verify
server state after the burst; duplicate 200s with single server-side effect is
not a finding. One run proving it is enough; races are probabilistic, so rerun
with higher `--concurrency` (30–50) and `--repeat 5` before concluding "not
vulnerable".

For HTTP/2 targets, the **single-packet attack** (all requests in one TCP
packet, zero network jitter) via Burp Turbo Intruder or Repeater's
"Send group in parallel" is strictly better — see
`references/race-conditions.md` for the Turbo Intruder `engine=Engine.BURP2`
script.

On a confirmed race, `race_runner.py --finding-out` emits a ready
`findings.report` payload (WSTG-BUSL-04 / CWE-367, scope `endpoint`, evidence
containing the concurrent request and the duplicated success responses) —
review, set severity by impact (money/credit duplication = high/critical),
and submit it via the `finding-report` skill.

---

## Phase 4 — Prove impact and report

A logic finding is only as strong as its proof. For each confirmed abuse:

1. **Capture the minimal request sequence** that reproduces it: the legitimate
   step(s), the tampered/skipped/raced request (full HTTP), and the response
   or subsequent state read that shows the broken outcome (order marked paid,
   balance = 2× expected, role = admin).
2. **Quantify impact in business terms**: money gained/lost per execution,
   privilege obtained, limit multiplier achieved.
3. **Report** via the `finding-report` skill → `findings.report`:
   scope `endpoint`, `target_ref` = the abused URL, severity by impact,
   classification = the matching `WSTG-BUSL-NN` plus a CWE
   (CWE-840 generic logic, CWE-367 race, CWE-841 workflow, CWE-602 client-side
   enforcement, CWE-20 data validation), and the full HTTP exchange in
   `evidence`. Exact payload shape: `references/rupu.md`.
4. **Mark coverage** honestly: every step probed → `tested`; every confirmed
   abuse → `exploited`. Workflows checked clean are still valuable coverage —
   mark them `tested` so the matrix shows BUSL was done.

**Chaining out:** money/limit abuses stand alone; role/status tampering hands
off to authorization testing (IDOR/privilege escalation); upload workflows
hand off to `file-upload-testing`; any client-side-trusted token worth
cracking hands off to session/crypto testing. Emit each handoff as a work unit
so nothing is dropped.
