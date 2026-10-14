# WSTG-BUSL test cases — concrete attack catalog

Per-case detail backing SKILL.md Phase 2. Every parse/confirm step below ends
in rupu output — `assets.mark` the route `tested`/`exploited` and
`findings.report` on confirmation (shapes in `rupu.md`).

---

## WSTG-BUSL-01 — Test Business Logic Data Validation

Target: every client-supplied value with business meaning. The server must
re-derive price/total/limits from its own data; prove when it doesn't.

### Numeric payload set (quantities, amounts, counts)

```
-1  -0.01  -999999  0  0.0001  0.5  1.00000001
2147483647  2147483648  4294967296      (int32/uint32 edges)
9223372036854775807  9223372036854775808 (int64 edge)
9999999999999999999  1e308  1e-308  Infinity  -Infinity  NaN
0x10  010  1,000  1.000  "1"  [1]  {"$gt":0}  null  true
```

Watch for: order accepted with negative/zero total; integer overflow wrapping
a large quantity to a small charge; float precision shaving
(`price=19.999999999` stored as `19.99`, charged as `20.00` or vice versa);
type-juggling (`"quantity":"1e2"` honored as 100 by one layer, 1 by another).

### Price / total / discount tampering

1. Capture the add-to-cart / checkout request. Identify every money field the
   client sends: `price`, `unit_price`, `total`, `subtotal`, `discount`,
   `discount_pct`, `tax`, `shipping`, `fee`, `amount`, `amount_cents`.
2. Replay with: `price=0.01`, `price=-10`, `total=0`, `discount=100`,
   `discount=110`, `tax=-<subtotal>`, `shipping=-5`.
3. Mismatch attacks: correct `total` but tampered line items; tampered `total`
   with correct items — find which one the server trusts.
4. Hidden form fields and data-attributes: anything rendered into the page
   (`<input type=hidden name=price value=49.99>`) and posted back is yours.
5. Payment-gateway handoff: tamper the `amount` passed *to* the gateway, and
   separately tamper the amount in the *callback/return* request. Many apps
   verify the gateway signature but not that the paid amount matches the order.

### Currency & unit abuse

- Switch currency code at the last step: `currency=USD` → `IDR`/`VND`/`JPY`.
- Pay in a zero-decimal currency where the integer is interpreted differently
  (`amount=1000` JPY vs `amount=1000` cents USD).
- Unit confusion: `amount` vs `amount_cents` — send `amount_cents=1`.

### Cross-field / referential consistency

- `item_id` of product A + `price_id`/`sku` of cheaper product B.
- Loyalty points: earn on gross, refund on net; buy with points, refund in
  cash; convert points→credit→points at mismatched rates (arbitrage loop).
- Date fields: book end-before-start (negative-duration rental = credit),
  birthdate in the future for age-gated discounts.

---

## WSTG-BUSL-02 — Test Ability to Forge Requests

- **Parameter values the UI never offers.** Enumerate enums: seen
  `type=basic`? try `type=premium|internal|admin|test|staff`. Seen
  `status=pending`? try `status=approved|paid|shipped|refunded`.
- **Guess sibling actions.** For every verb seen, try its CRUD/affirmative
  siblings on the same resource:
  `cancel→approve/complete/refund/reopen`, `view→edit/delete/export`,
  `request→grant`, `invite→accept` (accept your own invite as the inviter).
  Also method swaps: the `GET /admin/users` that 403s may honor
  `POST`/`PUT`/`DELETE`, and vice versa.
- **Add undocumented parameters** to every state-changing request:
  `debug=1 admin=1 test=1 internal=1 force=1 skip_validation=1 dry_run=0`
  `role=admin is_admin=true verified=true approved=true discount=100`
  (JSON bodies: add the keys; mass assignment frameworks bind them silently.)
- **Mobile/legacy/API parity**: the same action often exists at `/api/v1/...`,
  `/api/v2/...`, `/m/...`, `/graphql` with weaker validation. Replay the
  tampered request on every parallel surface.

---

## WSTG-BUSL-03 — Test Integrity Checks

- **Mass assignment**: on any create/update endpoint accepting JSON, merge in
  server-only keys and diff the resulting object:
  `{"role":"admin","balance":100000,"credits":9999,"verified":true,`
  `"owner_id":1,"plan":"enterprise","email_verified":true}`.
- **Opaque blob tampering** — decode everything:
  - Base64 JSON state (`eyJ...`): edit, re-encode, resubmit.
  - JWT: `alg:none`, empty signature, swap `kid`, re-sign with a public key
    (RS256→HS256), tamper claims (`role`, `sub`, `exp`). Does the server
    actually verify, or just decode?
  - "Signed" form state (`__VIEWSTATE`-style, Rails/Django signed cookies):
    strip the signature portion; if accepted, integrity is theater.
- **Stale-value replay**: capture a token/blob when state was favorable (price
  low, discount active, role elevated) and replay it after state changed.
- **Non-editable field tampering**: fields the UI renders read-only
  (username, email, account number, tier) — the server may still bind them.

---

## WSTG-BUSL-04 — Test for Process Timing (races & timing oracles)

Concurrency technique is in `race-conditions.md`. Case checklist:

**Limit-overrun targets** (single state, N requests):
coupon/promo redemption · gift-card balance spend · wallet withdrawal/transfer
· cashback/referral credit · one-per-user purchase · vote/like/rating · review
submission for bonus · free-trial activation · invite-code use · rate-limited
OTP guess (race the counter) · lottery/draw entry.

**Multi-step (state-machine) races** — two *different* requests in parallel:
- `apply_coupon` ∥ `checkout_complete` (coupon applies after total locked)
- `change_cart` ∥ `pay` (pay the old total for the new cart)
- `request_refund` ∥ `request_refund` and `refund` ∥ `spend`
- `change_email` ∥ `verify_email` (verify the new address with the old link)
- `delete_account` ∥ `transfer_out`
- password-reset token: `use_token` ∥ `use_token` (single-use token ×2)

**Timing oracles**: a slow payment-gateway callback can leave an order in
`authorized-but-unverified` for seconds — act (ship/download/redeem) inside
the window. Measure step durations from your proxy history to find windows.

**Confirm server-side**, never from HTTP alone: after the burst, re-read the
balance/order list/coupon state. Finding = requests + duplicated effect.
CWE-367 (TOCTOU) or CWE-362; WSTG-BUSL-04.

---

## WSTG-BUSL-05 — Test Number of Times a Function Can Be Used Limits

Serial (non-race) limit bypass:

- **Pure replay**: resend the exact successful request. Idempotency keys
  present? Change/remove them.
- **Lifecycle laundering**: apply coupon → remove → re-apply; add item → check
  out → cancel → credits kept? refund to a different payment method than paid?
- **Identifier variants**: coupon `SAVE10` vs `save10`, trailing
  space/tab/newline, URL-encoded, Unicode confusables (`ЅAVE10`), inner
  nulls (`SAVE%0010`).
- **Identity variants** for per-user limits: `user+1@example.com`,
  `u.ser@example.com` (Gmail-style dot folding), new session/device/IP,
  OAuth-vs-password accounts for the same email.
- **Surface variants**: web endpoint capped, API endpoint not; v1 capped, v2
  not; the "resend code" cap distinct from the "verify code" cap.
- **Counter location**: if the attempt counter lives in a cookie or hidden
  field, delete/reset it.

---

## WSTG-BUSL-06 — Test for the Circumvention of Workflows

Method: list the ordered requests R1..Rn of the workflow, then systematically
send: Rn alone · R1,Rn · Rn-1 skipped · Ri twice · Ri,Rj swapped · Ri with a
different session · Ri with another user's object ids.

High-value instances:
- **Pay-step skip**: call the order-confirmation/thank-you/complete endpoint
  with a valid `order_id` whose payment never happened. Also: start payment,
  abandon at the gateway, call the success-return URL yourself (forge
  gateway-callback parameters: `status=success&txn=anything`).
- **Lock-step bypass**: edit the cart *after* total lock; change shipping
  country after tax calc; upgrade seat/room after price fix.
- **Verification bypass**: POST to the resource gated behind email/phone/KYC
  verification directly; keep `verified=true` across an email change;
  predictable verification tokens.
- **Approval bypass**: self-approve by calling the approver's endpoint with
  your session; submit → edit-after-approval (approved object, swapped
  content).
- **Backward transitions**: cancelled→active, refunded→paid, by replaying the
  earlier transition request.
CWE-841; overlaps WSTG-ATHZ when crossing user boundaries — file both ids.

---

## WSTG-BUSL-07 — Test Defenses Against Application Misuse

Not an exploit — an amplifier. Probe and record whether the app reacts to:
200 wrong coupon codes in a minute; 50 transfers in 10s; navigation that
violates the state machine (payment before cart); input tampering from one
session repeatedly. Expected defenses: lockout, step-up auth, CAPTCHA,
alerting, session kill. Absence = finding (low/medium, CWE-778/CWE-799) and a
sentence in every other BUSL finding's evidence ("no abuse detection
interfered with N attempts").

---

## WSTG-BUSL-08 / 09 — Unexpected / Malicious File Upload

Hand the upload mechanics (extension/content-type/magic-byte bypass, webshell,
polyglots) to the `file-upload-testing` skill — emit a work unit per upload
route. Keep the *logic* angle here:

- Import files that set business values: CSV/XLSX product import with
  `price=0`, user import with `role=admin`, bulk credit import re-imported
  twice.
- Upload against another user's object (review image on someone else's
  product, invoice into another tenant) — ATHZ overlap.
- Quota/billing abuse: free-tier storage via unbounded versions/thumbnails.
