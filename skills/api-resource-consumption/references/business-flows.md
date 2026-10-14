# Sensitive Business-Flow Abuse (API6:2023)

API6 is not about broken requests — every call in the flow is individually
legitimate. The vulnerability is that **nothing stops one actor from running
the flow N times programmatically**. Your job: identify flows where scale =
harm, script them end-to-end, and show the Nth success.

## 1. Flow catalogue — what to look for and why it hurts

| Flow | Harm at scale | Typical endpoints |
|---|---|---|
| Purchase / checkout | Scalping: bot buys the whole drop before humans can | `POST /cart`, `POST /checkout`, `POST /orders` |
| Cart / reservation hold | Inventory hoarding: hold stock without paying, deny real buyers (also: hold then release = price/availability manipulation) | `POST /cart/items`, `POST /reservations` |
| Account creation | Sybil base for every other abuse; referral fraud; spam infra | `POST /signup`, `POST /register` |
| Coupon / promo redemption | Direct monetary loss; single-use codes redeemed N times across N accounts | `POST /coupons/redeem`, `POST /promo` |
| Referral / invite rewards | Self-referral loops: invite your own sybils, collect both-side bonuses | `POST /referrals`, `POST /invites` |
| Loyalty / points earn | Point farming via repeatable earn actions (check-in, review, share) | `POST /checkin`, `POST /points/earn` |
| Review / comment / message post | Spam, SEO abuse, reputation flooding, harassment at scale | `POST /reviews`, `POST /comments`, `POST /messages` |
| Vote / like / rating | Ranking manipulation — one actor, thousands of votes | `POST /votes`, `POST /ratings`, `POST /likes` |
| Booking / appointment | Slot exhaustion: book every slot, deny service, optionally cancel-and-rebook | `POST /appointments`, `POST /bookings` |
| Free-tier provisioning | Resource theft: N free trials / sandboxes / compute credits | `POST /trials`, `POST /workspaces` |
| Price/stock lookup | Competitive scraping (lower severity; note if explicitly sensitive to the business) | `GET /products`, `GET /prices` |

Pick flows from the discovery inventory by matching these shapes, plus anything
the operator's engagement notes call commercially sensitive.

## 2. The friction checklist

For each flow, test for each control's **presence AND effectiveness**:

1. **Captcha / human-proof** — present on any step? If present: is it validated
   server-side (replay the request with the captcha field removed, empty, or a
   previously-used token)? Mobile-API variants of the same flow often omit it
   entirely — check `/mobile/`, `/v1/` vs `/v2/`, and app-specific hosts.
2. **Per-account cap** — can one account repeat the action? If capped, how high?
3. **Global/cross-account correlation** — do N fresh accounts from one IP /
   device / card get linked? Test by running the flow across sybil accounts.
4. **Velocity checks** — does doing it fast (vs. spaced out) change anything?
   Run 10 iterations at 0 delay vs 10 at 30 s and compare.
5. **Device fingerprinting** — is there a device-ID/fingerprint field? Is it
   validated, or does a random UUID per iteration pass?
6. **Email/phone verification** — required? Do plus-addressed
   (`user+{{i}}@example.net`), dotted-Gmail-style, or disposable-domain
   addresses pass? Is verification actually enforced before the valuable step,
   or can you call the post-verification endpoint directly?
7. **Payment/identity friction** — for purchase flows: is a hold placed per
   cart? Can carts be abandoned without penalty and recreated?

Every "no" on this checklist for a sensitive flow is a line in the finding.

## 3. Scripting the flow

Build a flow template for `scripts/flow_abuse.py`. Example — signup +
self-referral farming:

```json
{
  "name": "signup-referral-farm",
  "variables": {
    "base": "https://api.example.com",
    "referral_code": "FRIEND-7X2K"
  },
  "steps": [
    {
      "name": "signup",
      "method": "POST",
      "url": "{{base}}/v1/signup",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"email\":\"probe+{{i}}-{{rand}}@example.net\",\"password\":\"S9!{{uuid}}\",\"referral\":\"{{referral_code}}\"}",
      "extract": {"token": "\"access_token\"\\s*:\\s*\"([^\"]+)\""},
      "success": {"status": [200, 201]}
    },
    {
      "name": "claim-bonus",
      "method": "POST",
      "url": "{{base}}/v1/rewards/claim",
      "headers": {"Authorization": "Bearer {{token}}",
                  "Content-Type": "application/json"},
      "body": "{\"type\":\"referral_signup\"}",
      "success": {"status": [200], "body_regex": "\"credited\"\\s*:\\s*true"}
    }
  ]
}
```

Run: `python3 scripts/flow_abuse.py --flow flows/signup-referral.json
--iterations 50 --delay 0.2 --out reports/flow-signup.json`.

Design notes:
- `extract` regexes capture values (tokens, order IDs, coupon codes) into the
  variable scope for later steps **in the same iteration**; builtins `{{i}}`,
  `{{rand}}`, `{{rand_hex}}`, `{{uuid}}`, `{{ts}}` regenerate per iteration.
- For purchase/booking flows, make the last step the one that consumes the
  scarce resource and set an explicit `success.body_regex` so false positives
  (200-with-error-body) don't inflate the count.
- For vote/review flooding, a single-step flow with `{{rand}}`-varied content
  is enough; vary the content so dedup filters are tested too.
- For captcha-bearing flows, first script the flow with the captcha field
  stripped/replayed — if that passes, the captcha is decorative and the finding
  is stronger.

## 4. Choosing N and reading the result

- N = 50 proves "no friction" convincingly for most flows; N = 10 is enough
  when each iteration consumes real inventory or sends real notifications —
  then extrapolate in the write-up.
- `no-friction` verdict → finding. Headline: "one script created 50 accounts
  and claimed 50 referral bonuses in 43 seconds; no captcha, cap, or velocity
  control fired." Evidence: the flow report JSON + the exchange of iteration 1
  and iteration N.
- `friction-at-N` → characterize the control (what fired, at which step, at
  which N, keyed on what), then attack it with the bypasses from
  rate-limiting.md (IP-header rotation, identifier encoding, plus-addressing,
  path variants) and re-run. Document whichever state you end in.
- Clean up what the engagement rules require (created accounts, held carts) and
  list created artifacts in the report so the operator can hand them to the
  client.

CWE mapping: CWE-799 (improper control of interaction frequency) for the
general case, CWE-837 (improper enforcement of a single unique action) for
"once-per-user" violations like multi-redeem coupons or repeat votes, CWE-770
when the same gap is pure resource exhaustion. Severity rides on business
impact — monetary flows (coupons, referrals, inventory) are High; spam/vote
flows typically Medium.
