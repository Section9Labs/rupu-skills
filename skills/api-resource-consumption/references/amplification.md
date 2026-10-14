# Resource Amplification (API4:2023)

The pattern everywhere: **measure the baseline cost of one honest request, then
show how a crafted request multiplies that cost.** Impact = ratio, evidence =
the before/after request/response pairs with timings and sizes.

Timing/size capture with curl:

```
curl -sk -o /dev/null -w 'status=%{http_code} bytes=%{size_download} time=%{time_total}\n' \
  'https://api.example.com/v1/items?limit=10'
curl -sk -o /dev/null -w 'status=%{http_code} bytes=%{size_download} time=%{time_total}\n' \
  'https://api.example.com/v1/items?limit=100000'
```

Run each probe 3 times, use the median; one slow sample proves nothing.

## 1. Pagination abuse

For every list endpoint, enumerate the pagination param (`limit`, `per_page`,
`page_size`, `pageSize`, `count`, `size`, `top`, `$top`, `max_results`, `first`)
and probe:

| Probe | What it tests |
|---|---|
| `?limit=100` → `1000` → `10000` → `100000` | Hard cap present? Where? Note the knee in response time/size. |
| `?limit=-1`, `?limit=0` | Sentinel values meaning "all rows" in many ORMs. |
| `?limit=2147483647` | Int-max; cap bypass or 500. |
| remove the param entirely | Defaults are sometimes unbounded. |
| `?limit=100&limit=100000` | Parameter pollution — validator reads first, query builder reads last. |
| `?limit[]=100000`, `?limit=1e9` | Type-confusion past the validator. |
| `?offset=99999999` | Deep-offset `OFFSET` scans are O(n) in most databases — latency grows even with small limits. |

A single request returning the whole table (size × time blow-up) is both a DoS
primitive and frequently an excessive-data-exposure assist — cross-reference
with the data-exposure phase.

## 2. Unbounded search / export / report endpoints

- Search with the broadest input: empty string, `*`, `%`, single character,
  `a` — compare result counts and timings.
- Export endpoints (`/export`, `format=csv|pdf|xlsx`, "download report"): these
  typically materialize the full dataset server-side regardless of pagination.
  One export call can equal thousands of list calls. Time it; check whether
  concurrent exports are allowed (fire 5 in parallel and watch latency of an
  unrelated baseline endpoint degrade — that cross-endpoint degradation is the
  cleanest DoS evidence you can capture without sustained load).
- Async-job patterns (`202` + job ID): check whether job creation is limited;
  unbounded job enqueue is the amplification even if each job is slow.

## 3. Expansion / projection parameters

`?include=`, `?expand=`, `?fields=`, `?embed=`, GraphQL-ish REST hybrids:

- Stack every documented relation: `?include=orders,items,reviews,author,...`.
- Nest: `?expand=orders.items.product.reviews.author` — each level is a
  potential N+1 query storm; latency grows multiplicatively, size moderately.
  Latency growth without size growth = database amplification, the more
  dangerous kind.
- Combine with pagination abuse: `?limit=10000&expand=everything`.

## 4. Request-body cost

- **Size**: send 1 MB, 10 MB, 50 MB JSON bodies. Does anything reject on
  `Content-Length` before parse? If parse time scales with size, that CPU time
  is attacker-controlled.
- **Depth**: `{"a":{"a":{"a":...}}}` 1000+ levels — recursive parsers stack-
  crash or burn CPU. Generate with
  `python3 -c 'print("{\"a\":"*2000 + "1" + "}"*2000)'`.
- **Array fan-out**: batch endpoints (`items: [...]`) with 10k–100k elements;
  each element may trigger per-item queries, webhooks, or emails.
- **Key duplication / hash-collision shapes**: 100k distinct keys in one object.
- **Content-Encoding: gzip** request bodies: a few KB on the wire inflating to
  hundreds of MB in the parser (request-side decompression bomb). Build with
  `python3 -c 'import gzip,sys; sys.stdout.buffer.write(gzip.compress(b"["+b"0,"*50_000_000+b"0]"))' > bomb.json.gz`
  and send with `curl -H 'Content-Encoding: gzip' --data-binary @bomb.json.gz`.

## 5. File-upload bombs

Where uploads are accepted:
- Oversized files (no size cap?).
- **Zip bombs** where archives are server-side expanded (import features,
  plugin/theme uploads): nested zips or high-ratio single entries. Probe with
  a modest 10:1 ratio first and watch processing time before anything bigger.
- Image/video uploads feeding a thumbnailer: a 50000×50000-pixel but tiny-on-
  disk PNG ("pixel flood") makes the resizer allocate gigabytes.

## 6. ReDoS

Target: any input echoed through server-side validation (email, URL, phone
formats), search-with-regex, or markdown/log parsing.

Probe strings (grow the `a`-run linearly: 10, 20, 30, 40 chars — catastrophic
backtracking shows *exponential* latency growth, which is the fingerprint):

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@
a@a.a@a.a@a.a@a... (email validators)
((((((((((a))))))))))  (nested-group inputs for URL/expression parsers)
```

Evidence table: input length vs median latency over 3 runs. 10→20 chars doubling
latency is linear (fine); 10→20 chars going 50 ms → 5 s is ReDoS (CWE-1333,
report under the API4 umbrella). Stop as soon as the curve is unambiguous — a
30 s hang IS the proof; do not fire it in parallel.

## 7. Costly third-party operations

Endpoints where every call costs the target real money or a scarce quota:

- SMS/voice OTP send, email send, push notification.
- PDF/report/image rendering, video transcode.
- Geocoding/maps/AI-model calls proxied to a paid upstream.

Here the test is simply the rate-limit probe (see rate-limiting.md) scoped to
the costly op: `ratelimit_probe.py --count 30` against `/v1/otp/send`. 30
unthrottled OTP sends ≈ 30 billed SMS from one script in seconds; extrapolate
in the finding ("~X calls/hour from a single client ⇒ unbounded spend") rather
than demonstrating the full hour. If the destination (phone/email) is
attacker-chosen, you also have an SMS/email flooding primitive against third
parties — note both impacts.

## 8. Writing it up

Each amplification finding needs: the baseline exchange, the amplified
exchange, the ratio (time, bytes, or dollars-per-call), and the missing control
(no max page size, no body cap, no regex timeout, no quota). CWE-770 (allocation
without limits) is the default; CWE-1333 for ReDoS; CWE-409 for decompression
bombs. Report via `findings.report` per references/rupu.md and raise the
endpoint to `exploited` once the ratio is demonstrated.
