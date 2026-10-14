---
name: grpc-testing
description: Enumerate and attack gRPC services with grpcurl — reflection-based service/method discovery, proto/protoset-driven invocation when reflection is off, metadata (auth) manipulation, and hand-off of enumerated methods to authorization and injection testing. Use in phase 7 of the api-testing flow whenever the target API speaks gRPC (internal microservices, mobile backends, HTTP/2 ports like 50051/443 with application/grpc).
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# gRPC Testing

gRPC is HTTP/2 + protobuf. Once you can enumerate services and methods, every
REST-style authorization and injection test applies — the only difference is
the transport and the message encoding. `grpcurl` is the primary tool: it
speaks JSON on your side and protobuf on the wire.

Imports: `work-units` (splitting/fan-out), `coverage-assets` (`assets.mark`
wiring), `finding-report` (`findings.report` contract), `api-authorization`,
`api-injection`, `api-resource-consumption` (follow-on testing).

## 1. Identify the gRPC surface

Signals that a port speaks gRPC:
- Open 50051/50052 (conventional), or 443/8443 negotiating HTTP/2 with ALPN `h2`.
- HTTP responses with `content-type: application/grpc` or `grpc-status` trailers.
- Mobile app traffic with protobuf bodies over HTTP/2.

Establish the connection mode first — this decides the flag on every grpcurl call:

```sh
grpcurl -plaintext 203.0.113.20:50051 list        # h2c, no TLS (common internally)
grpcurl -insecure  203.0.113.20:443 list          # TLS, skip cert verification
grpcurl 203.0.113.20:443 list                     # TLS, verify (default)
```

If the service sits behind a virtual-host-routing proxy, set `-authority
grpc.example.com`. Pass auth as metadata with `-H "authorization: Bearer <tok>"`
(repeatable). Full connection/TLS/proxy flags: `references/grpcurl.md`.

Plaintext gRPC on a production network segment is itself a transport finding
(cleartext credentials/PII on the wire).

## 2. Enumerate — reflection first

If server reflection is enabled, the API inventory is free:

```sh
grpcurl -plaintext 203.0.113.20:50051 list                          # services
grpcurl -plaintext 203.0.113.20:50051 list my.pkg.UserService       # methods
grpcurl -plaintext 203.0.113.20:50051 describe my.pkg.UserService   # full schema
grpcurl -plaintext 203.0.113.20:50051 describe my.pkg.GetUserRequest # message fields
```

`describe` on a service prints every `rpc Name (Input) returns (Output)` line,
including `stream` markers. `describe` on a message type gives you the exact
field names/types to build `-d` payloads. Reflection exposed in production is
a reportable information-disclosure finding on its own — note it, then use it.

Automate this with the bundled script, which runs list/describe, parses the
output, and emits a normalized inventory plus a rupu work-unit array:

```sh
python3 scripts/grpc_enum.py 203.0.113.20:50051 --plaintext \
  -H "authorization: Bearer eyJ..." \
  -o reports/grpc-203.0.113.20
# -> reports/grpc-203.0.113.20-inventory.json
# -> reports/grpc-203.0.113.20-units.json   (one unit per method, atomic write)
```

Mark coverage as you enumerate: the service as `api:service` (`mapped`) and
each method as `api:endpoint` with `http_route` set to
`my.pkg.Service/Method` (`mapped`). Exact `assets.mark` shapes and the
fan-out wiring: `references/rupu.md` (defer to `coverage-assets` for the
tool itself).

## 3. Enumerate — reflection off

No reflection means you need descriptors. In order of preference:

1. **Protos from the client.** Mobile apps and desktop clients ship or embed
   them: decompile the APK/IPA, grep for `.proto` strings or generated stubs
   (`*Grpc.java`, `*_pb2.py`, `*.pb.go`), reconstruct messages from the
   generated code. CI artifacts, SDK packages, and public repos of the vendor
   are other sources.
2. **Build a protoset** once you have protos:
   `protoc --descriptor_set_out=svc.protoset --include_imports -I ./protos svc.proto`
3. **Point grpcurl at them**:
   ```sh
   grpcurl -import-path ./protos -proto svc.proto -plaintext 203.0.113.20:50051 \
     describe my.pkg.UserService
   grpcurl -protoset svc.protoset -plaintext 203.0.113.20:50051 list
   ```
4. **No descriptors at all**: brute-force plausible `pkg.Service/Method` names
   (grpc-status 12 UNIMPLEMENTED = wrong name; anything else = hit), or proxy
   a real client through Burp — its protobuf/gRPC support deserializes bodies
   to JSON for manual tamper and replay. `grpc_cli` (ships with gRPC) is an
   alternative CLI with the same list/call model.

Details and extraction recipes: `references/grpcurl.md`.

## 4. Invoke methods

```sh
grpcurl -plaintext -d '{"id": 1001}' 203.0.113.20:50051 my.pkg.UserService/GetUser
echo '{"id": 1001}' | grpcurl -plaintext -d @ 203.0.113.20:50051 my.pkg.UserService/GetUser
```

- `-d @` reads JSON from stdin — use for large payloads and streaming (one
  JSON doc per client-stream message).
- `-emit-defaults` prints zero-valued fields so you see the full response shape.
- `-format text` for protobuf text format; JSON is the default and what you want.
- `-H` metadata is sent on every call; `-rpc-header` for per-RPC metadata on
  streams; `-max-time 10` to bound long-lived streams.
- Read `grpc-status` in the error output: `16 UNAUTHENTICATED` /
  `7 PERMISSION_DENIED` means authz is in play; `3 INVALID_ARGUMENT` leaks
  validation internals; `12 UNIMPLEMENTED` means wrong method name. Status
  table: `references/grpcurl.md`.

Raise each probed method to `depth: "tested"` via `assets.mark`.

## 5. Security testing — same logic as REST

Fan out the units file from step 2 and apply `api-authorization` per method:

- **BOLA**: tamper object identifiers inside the message —
  `-d '{"id": 1002}'` with user A's token where 1002 belongs to user B.
  Any field named `id`, `*_id`, `owner`, `account`, `tenant` is a candidate.
- **BFLA**: invoke admin/privileged-looking methods (`Delete*`, `Admin*`,
  `Set*`, `*Internal*`, anything in an `admin`/`internal` package) with a
  low-privilege identity's metadata. gRPC services frequently check auth at
  the interceptor level but not per-method.
- **Metadata auth bypass**: replay the same call with the `authorization`
  metadata dropped entirely, with an empty value, with a forged/expired token,
  and with alternate header names (`x-api-key`, `cookie`, `grpc-metadata-*`
  if a gateway translates). A 0 OK without credentials on a method that
  returned 16 with bad credentials is a confirmed bypass.
- **Injection**: string fields in messages flow into SQL/NoSQL/command/LDAP
  sinks exactly like REST parameters — apply `api-injection` payloads via
  `-d` JSON values.
- **Resource abuse**: oversized messages (servers default to 4 MiB receive
  limit — probe above it and watch for 8 RESOURCE_EXHAUSTED vs. acceptance),
  unbounded client streams (`-d @` with an endless stdin producer), and
  server streams held open — hand off to `api-resource-consumption`.

Evidence for every confirmed issue is the paired request/response: capture the
exact grpcurl command, `-d` payload, metadata, and the JSON response or
`grpc-status` line. With `-v`/`-vv` grpcurl prints headers and trailers too.

## 6. Record results

- Confirmed authz break, auth bypass, injection, or impactful resource abuse →
  `findings.report` under the `api` profile, pinned to the `api:endpoint` by
  its `http_route` coordinate (`my.pkg.Service/Method`), with an
  `http_exchange` evidence block. Field contract: the `finding-report` skill.
- Raise the endpoint to `depth: "exploited"` only when real impact is
  confirmed (another tenant's data returned, privileged action executed).
- Reflection-in-production, plaintext transport, and verbose
  INVALID_ARGUMENT internals are lower-severity findings pinned to the
  `api:service`.

Concrete rupu wiring (fan-out, dispatch, asset shapes): `references/rupu.md`.
