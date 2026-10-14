# grpcurl reference (fullstorydev/grpcurl)

`grpcurl [flags] <address> <verb>` where verb is `list`, `describe`, or a
fully-qualified method `pkg.Service/Method` (dot form `pkg.Service.Method`
also accepted). Address is `host:port`; default port 443 for TLS, 80 for
`-plaintext` — gRPC servers rarely sit on defaults, so always give the port.

## Connection and TLS

| Flag | Meaning |
|---|---|
| `-plaintext` | No TLS; HTTP/2 cleartext (h2c). Typical for internal services on 50051. |
| `-insecure` | TLS but skip certificate verification. Use against self-signed/dev certs. |
| (default) | TLS with verification against system roots. |
| `-cacert file.pem` | Custom CA bundle for verification. |
| `-cert c.pem -key k.pem` | Client certificate (mTLS). Test whether the server actually requires it. |
| `-servername name` | TLS SNI override. |
| `-authority grpc.example.com` | `:authority` pseudo-header override — needed behind vhost-routing proxies/ingresses; also useful to probe host-header routing confusion. |
| `-connect-timeout 5` | Seconds to wait for connection establishment (default 10). |
| `-keepalive-time 10` | HTTP/2 keepalive pings every N seconds. |
| `-max-time 15` | Max seconds for the whole operation — bounds hung streams. |
| `-max-msg-sz 16777216` | Max response message size grpcurl will accept (default 4 MiB). Raise it when probing large-response methods. |
| `-proxy socks5://127.0.0.1:9050` / env `HTTPS_PROXY` | Route through a proxy (recent versions; otherwise use proxy env vars). |
| `-unix` | Address is a Unix domain socket path. |

## Metadata (headers)

| Flag | Meaning |
|---|---|
| `-H "authorization: Bearer <tok>"` | Request metadata; repeatable. This is how auth travels in gRPC. |
| `-rpc-header "k: v"` | Metadata sent per-RPC (relevant for streams); repeatable. |
| `-reflect-header "k: v"` | Metadata sent only on reflection requests — some servers gate reflection behind auth. |
| `-expand-headers` | Expand `${ENV}` references inside header values. |
| `-user-agent "..."` | Override user agent. |

Auth-bypass matrix per method: (a) no `-H` at all, (b) `-H "authorization:"`
empty, (c) expired/forged token, (d) other identity's valid token, (e)
alternate carrier headers (`x-api-key`, `cookie`). Compare grpc-status and
response bodies across the matrix.

## Enumeration

```sh
grpcurl -plaintext 203.0.113.20:50051 list
# grpc.reflection.v1alpha.ServerReflection
# my.pkg.UserService
# my.pkg.admin.AdminService

grpcurl -plaintext 203.0.113.20:50051 list my.pkg.UserService
# my.pkg.UserService.GetUser
# my.pkg.UserService.ListUsers

grpcurl -plaintext 203.0.113.20:50051 describe my.pkg.UserService
# my.pkg.UserService is a service:
# service UserService {
#   rpc GetUser ( .my.pkg.GetUserRequest ) returns ( .my.pkg.User );
#   rpc Watch ( stream .my.pkg.WatchRequest ) returns ( stream .my.pkg.Event );
# }

grpcurl -plaintext 203.0.113.20:50051 describe my.pkg.GetUserRequest
# message GetUserRequest { int64 id = 1; string tenant = 2; }

grpcurl -plaintext -msg-template 203.0.113.20:50051 describe my.pkg.GetUserRequest
# ...also prints a JSON template of the message — paste into -d and edit.
```

`describe` with no argument describes every exposed service. The presence of
`grpc.reflection.v1alpha.ServerReflection` (or `.v1.`) in `list` output is the
reflection-in-production observation.

Dump the whole schema for offline use / sharing with other agents:

```sh
grpcurl -plaintext -protoset-out dump.protoset 203.0.113.20:50051 describe
```

The resulting protoset works with `-protoset dump.protoset` even after
reflection is disabled, and feeds Burp/other tooling.

## Sources when reflection is off

- `-proto svc.proto -import-path ./protos` (both repeatable) — compile protos
  locally. All imports must resolve under the import paths.
- `-protoset file.bin` (repeatable) — precompiled descriptor set. Build with:
  `protoc --descriptor_set_out=svc.protoset --include_imports -I ./protos svc.proto`
- `-use-reflection` combined with `-proto`/`-protoset` merges both sources.
- Obtaining protos: decompile the mobile client (APK: `jadx`, look for
  generated `*Grpc` classes and `com.google.protobuf` descriptors embedded as
  byte arrays; iOS: strings in the binary), check npm/pip/maven SDK packages,
  vendor GitHub, CI artifact stores, and `.pb.go`/`_pb2.py` files on
  compromised hosts. Generated code contains the full field numbering — enough
  to reconstruct the `.proto` by hand.
- Blind: call guessed names; `grpc-status 12 (UNIMPLEMENTED)` = no such
  method, `16/7/3/0` = method exists. Service names follow
  `company.product.v1.ThingService` conventions.

## Invocation

```sh
grpcurl -plaintext -d '{"id": 1001, "tenant": "acme"}' \
  203.0.113.20:50051 my.pkg.UserService/GetUser

echo '{"id": 1001}' | grpcurl -plaintext -d @ 203.0.113.20:50051 my.pkg.UserService/GetUser
```

| Flag | Meaning |
|---|---|
| `-d '<json>'` | Request body. For client/bidi streams, concatenate multiple JSON docs (whitespace-separated); each becomes one message. |
| `-d @` | Read body from stdin — large payloads, generated streams. |
| `-format json` / `-format text` | Request/response encoding (default json). |
| `-emit-defaults` | Include zero-valued fields in JSON output. |
| `-allow-unknown-fields` | Don't error on unknown fields in `-d` (probe for lenient parsers). |
| `-format-error` | Render RPC errors in the chosen format too. |
| `-v` / `-vv` | Verbose: resolved headers, trailers, timing, message sizes — capture for evidence. |

Bytes fields are base64 in JSON; well-known types (`Timestamp`, `Duration`,
`Any`) use their canonical JSON forms. `google.protobuf.Any` fields that the
server unpacks are a deserialization attack surface — try unexpected
`@type` URLs.

Exit code: 0 on grpc-status OK, otherwise `64 + status_code` is NOT used —
grpcurl exits non-zero and prints:

```
ERROR:
  Code: PermissionDenied
  Message: user 1001 may not read user 1002
```

## grpc-status cheat sheet

| Code | Name | Read as |
|---|---|---|
| 0 | OK | Call succeeded — check whose data came back. |
| 3 | INVALID_ARGUMENT | Validation ran; message text often leaks internals/stack frames. |
| 5 | NOT_FOUND | Object routing works; id enumeration oracle. |
| 7 | PERMISSION_DENIED | AuthN ok, authZ blocked — tamper ids/roles. |
| 8 | RESOURCE_EXHAUSTED | Size/rate limit hit — map the limit. |
| 12 | UNIMPLEMENTED | Method/service name wrong (or reflection off for that verb). |
| 13 | INTERNAL | Unhandled server error — your input reached something fragile. |
| 14 | UNAVAILABLE | Transport/LB problem, not an app answer. |
| 16 | UNAUTHENTICATED | Credentials missing/invalid — run the bypass matrix. |

Differential testing is the whole game: same call, different identity or
tampered field, compare status + body.

## Alternatives

- **grpc_cli** (ships with gRPC): `grpc_cli ls 203.0.113.20:50051 -l`,
  `grpc_cli call 203.0.113.20:50051 my.pkg.UserService.GetUser 'id: 1001'`
  (proto text format). Same reflection dependency.
- **Burp Suite**: proxy a real client (set the app's proxy / pin-bypass),
  enable the gRPC/protobuf extension (e.g. "gRPC-Web"/"Protobuf Decoder" or
  built-in HTTP/2 support) to deserialize bodies to editable JSON — best for
  tampering a live authenticated session; load the protoset dumped above for
  field names.
- **grpcui** (same author as grpcurl): `grpcui -plaintext 203.0.113.20:50051`
  gives a browser form UI over reflection — convenient for exploring deep
  message trees.
