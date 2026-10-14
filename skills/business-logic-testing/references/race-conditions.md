# Race-condition testing in depth (WSTG-BUSL-04)

A race window is the gap between a server's **check** (coupon unused? balance
sufficient? token valid?) and its **act** (mark used, debit, consume). Your job
is to land N requests inside one window. The window is often sub-millisecond,
so the technique is about removing jitter, not about raw volume.

---

## 1. Making requests truly concurrent

Three sources of jitter, and the countermeasure for each:

| Jitter source            | Countermeasure                                             |
|--------------------------|------------------------------------------------------------|
| TCP + TLS handshake      | **Connection warming** — open & handshake all K sockets first; optionally send a throwaway keep-alive `GET /` on each so server-side pools/caches are hot. |
| Network transit variance | **Last-byte sync** (HTTP/1.1) — send each request minus its final byte, barrier, then release the last bytes together. The server cannot start processing an incomplete request. |
| Even residual jitter     | **Single-packet attack** (HTTP/2) — put ~20–30 complete requests into one TCP packet on one connection; the kernel delivers them simultaneously. Zero network jitter. Requires HTTP/2 (one connection, multiplexed streams). |

Server-side first-request overhead also skews results: the *first* request to
hit a cold worker runs slower. Warming plus discarding the first run's results
handles this.

### Last-byte sync, by hand

1. Open K TCP connections, complete TLS on each.
2. Build the identical attack request with `Connection: close` and a correct
   `Content-Length`.
3. On each connection send `request_bytes[:-1]`.
4. Barrier-wait all threads.
5. Send the final byte on all connections; read responses.

This is exactly what `scripts/race_runner.py --sync last-byte` does.
`--sync barrier` sends whole requests after the barrier instead (use it when
a middlebox buffers incomplete requests, e.g. some WAFs/CDNs time out
partial bodies).

### Single-packet attack with Burp

- **Repeater**: put the request in a tab group (one tab per copy, 20–30
  copies), choose **Send group in parallel (single-packet attack)**. Burp uses
  HTTP/2 automatically when the server supports it.
- **Turbo Intruder** (BApp): `engine=Engine.BURP2` + `gate`:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)       # HTTP/2 single-packet
    for i in range(30):
        engine.queue(target.req, gate='race1')        # queue, do not send
    engine.openGate('race1')                          # release all at once

def handleResponse(req, interesting):
    table.add(req)
```

For HTTP/1.1-only targets use `Engine.THREADED` with
`concurrentConnections=30, requestsPerConnection=1` and the same
`gate`/`openGate` pattern (Turbo Intruder then does last-byte sync for you).

**Multi-endpoint races** (e.g. `apply_coupon` ∥ `complete_checkout`): queue
the two *different* requests behind the same gate — Turbo Intruder and
Repeater tab groups both support mixed requests. `race_runner.py` supports it
via multiple `--request-file` arguments (requests are distributed round-robin
across the K slots).

**Session-handling trap**: if each request needs a fresh single-use value
(CSRF token, nonce), pre-fetch K values first, template them in
(`race_runner.py --data` with `{SLOT}` substitution or Turbo Intruder
wordlist), *then* gate the sends.

---

## 2. Detecting a win

Never conclude from HTTP responses alone — confirm with server state.

1. **Response distribution** (first signal): group responses by
   `(status, body-length, body-hash)`. Expected for a correct app: exactly one
   success-shaped response, K−1 failures. **≥2 successes** = race candidate.
   Caveat: some apps return 200 for all and only act once — hence step 2.
2. **State check** (proof): immediately after the burst, read the authoritative
   state: wallet balance (debited 2×?), order list (two orders?), coupon-usage
   count, credit total. The finding's impact figure comes from here:
   `expected_effect × 1` vs `observed_effect × M` → limit multiplier M.
3. **Differential baseline**: run the same burst against an action that is
   *supposed* to be repeatable, to learn what K-successes "normally" looks
   like for this stack (helps rule out false reads from caching/CDN).

**Probabilistic, so persist**: a window of microseconds may need many trials.
Escalate: K=10 → 20 → 50; reruns (`--repeat 5`); off-peak vs peak; target the
specific backend node if a load balancer spreads your burst (session-affinity
cookie, or many bursts). Only after ~5 clean runs at K≥30 call it not
exploitable — and still note it as tested coverage.

**Window widening**: if check and act are separated by slow work (external
API, email send), a race that fails at micro-scale may succeed trivially —
pair the burst with a request that *slows* processing (large valid body,
heavy search parameter) to stretch the window.

---

## 3. race_runner.py usage reference

```
python3 scripts/race_runner.py
  --url URL | --request-file FILE [--request-file FILE2 ...]
  [--force-ssl] [--port N]                # for request files
  [--method POST] [-H 'Name: value' ...] [--data BODY | --data-file F]
  --concurrency 20          # K parallel requests
  --sync last-byte|barrier  # default last-byte
  --warm                    # keep-alive GET / per connection before the burst
  --repeat 1                # independent rounds
  --success-status 200,201  # success class (default: any 2xx)
  --success-regex REGEX     # AND-condition on body, e.g. '"ok":true'
  --timeout 10
  --output results.json     # full per-response + distribution summary
  --finding-out finding.json  # findings.report payload if ≥2 successes
```

Body templating: the literal `{SLOT}` in `--data` or a request-file body is
replaced per-thread with the slot index (0..K−1) — handy to make each request
distinguishable in server logs while keeping semantics identical, or to inject
pre-fetched per-request tokens from `--slot-values tokens.txt` (one per line).

Reading `results.json`:
- `distribution`: list of `{status, length, body_sha256_12, count}` — the
  success/failure split at a glance.
- `responses[*].recv_ms`: spread of completion times; a tight cluster (<5 ms)
  confirms the sync worked. If spread is wide, network jitter beat you — move
  the runner closer to the target or switch to single-packet via Burp.
- `successes`: count matching the success criteria. `race_suspected: true`
  when `successes >= 2`.

The emitted finding payload is a draft: verify server state, set `severity`
by monetary/privilege impact, paste the state-check evidence in, then submit
through the `finding-report` skill (shape in `rupu.md`).
