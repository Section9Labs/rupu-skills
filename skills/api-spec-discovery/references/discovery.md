# Spec Discovery Playbook

Full location catalogue and scraping techniques for finding an API's
definition. `scripts/fetch_spec.py` automates the probe list; this file is the
manual fallback and the depth behind each hit type.

## 1. Common spec locations

Probe each path on the API host, on `www.`, and on every discovered subdomain
(APIs frequently serve docs on a different vhost than production traffic):

```
/openapi.json  /openapi.yaml  /openapi.yml
/swagger.json  /swagger.yaml
/v2/api-docs                     # springfox (Swagger 2.0)
/v3/api-docs                     # springdoc (OpenAPI 3)
/v3/api-docs.yaml
/v3/api-docs/swagger-config      # springdoc group list -> urls[]
/v3/api-docs/{group}             # one doc per springdoc group
/api-docs  /api-docs.json  /api/api-docs
/api/openapi.json  /api/swagger.json  /api/v1/openapi.json
/swagger/v1/swagger.json         # ASP.NET Core Swashbuckle (v1..vN)
/swagger-resources               # springfox resource listing
/swagger-ui.html  /swagger-ui/  /swagger-ui/index.html
/docs  /redoc  /openapi.json     # FastAPI (UI at /docs, spec at /openapi.json)
/api-json                        # NestJS @nestjs/swagger default
/docs/api-docs.json              # Laravel l5-swagger (also /docs, /api/documentation)
/apidocs  /apidocs/swagger.json  # Flasgger
/swagger.json at app root        # Flask-RESTX / flask-restplus
/api-docs/v1/swagger.yaml        # Rails rswag
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/.well-known/openapi.json  /.well-known/schema-discovery
/graphql  /graphql/schema  /graphiql  /api/graphql  /v1/graphql
```

Also try each path under discovered base prefixes: `/api`, `/api/v1`, `/v1`,
`/rest`, `/service`, and the `basePath` seen in any JS bundle.

curl recipe (per path):

```bash
curl -skL -A 'Mozilla/5.0' -H 'Accept: application/json' \
     -o /tmp/body -w '%{http_code} %{content_type} %{url_effective}\n' \
     https://api.example.com/v3/api-docs
# httpie equivalent
http --verify=no --follow GET https://api.example.com/v3/api-docs Accept:application/json
```

Status reading: `200` with JSON → classify; `401/403` on a spec path still
confirms the file exists — retry with any harvested credentials/API key;
`200` HTML on `/docs` or `/swagger-ui.html` → parse the UI page (below).

## 2. Swagger-UI pages (UI exists, spec URL unknown)

The UI page or its init JS always names the spec it renders. Fetch the page
and its referenced JS, then extract:

```bash
curl -skL https://api.example.com/swagger-ui/index.html -o ui.html
grep -oE 'url[" ]*:[ ]*"[^"]+"' ui.html
grep -oE 'configUrl[" ]*:[ ]*"[^"]+"' ui.html
# modern swagger-ui loads swagger-initializer.js:
curl -skL https://api.example.com/swagger-ui/swagger-initializer.js
```

Patterns to match: `SwaggerUIBundle({ url: "/v3/api-docs" })`,
`urls: [{url: "/v3/api-docs/admin", name: "admin"}, ...]` (fetch **every**
entry — admin/internal groups are the prize), `configUrl: "/v3/api-docs/swagger-config"`.
Older springfox: `/swagger-resources` returns a JSON array of `location`
values. Redoc: `<redoc spec-url="/openapi.yaml">` or `Redoc.init('/openapi.json', ...)`.

## 3. JS bundle and HTML scraping

When no doc endpoint exists, the frontend still encodes the API surface:

```bash
# collect script URLs from the app
curl -skL https://example.com/ | grep -oE 'src="[^"]+\.js[^"]*"'
# fetch each bundle and mine it
curl -skL https://example.com/static/js/main.ab12cd.js -o main.js
grep -oE '"(/[a-zA-Z0-9_./{}-]*(api|openapi|swagger|graphql)[a-zA-Z0-9_./{}-]*)"' main.js
grep -oE 'basePath["\x27 ]*[:=]["\x27 ]*[^"\x27]+' main.js
grep -oE '"(GET|POST|PUT|PATCH|DELETE)"[ ,]+"(/[^"]+)"' main.js
grep -oE '(https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9_./-]*)' main.js | sort -u
```

Look for: axios/fetch base URLs (`baseURL:`), route tables, `.map` source maps
(`main.js.map` often contains the original source with full route definitions),
and inline `openapi`/`swagger` JSON blobs. Endpoints found here but absent from
any published spec are **shadow endpoints** (OWASP API9) — add them to the
request set manually.

## 4. GraphQL

Presence check and introspection:

```bash
curl -sk -X POST https://api.example.com/graphql \
  -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
# full introspection (schema == the spec)
curl -sk -X POST https://api.example.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { kind name fields(includeDeprecated:true){ name args { name type { kind name ofType { kind name } } } type { kind name ofType { kind name } } } inputFields { name } enumValues { name } } } }"}' \
  -o reports/graphql-schema.json
```

If introspection is disabled, field suggestions in error messages
(`Did you mean ...`) still enumerate the schema — fuzz field names and collect
suggestions. `/graphql/schema`, `/graphql.schema.json`, and `schema.graphql`
sometimes serve the SDL directly. Treat each query/mutation as one operation
in the normalized request set (`POST /graphql`, body = `{"query": ...}`).

## 5. Postman public documentation

Teams publish collections at `documenter.getpostman.com/view/<id>/<slug>` and
`www.postman.com/<team>/workspace/...`. Search the Postman public API network
and general dorks for the target's name/domain:

```
site:documenter.getpostman.com "example.com"
site:postman.com "api.example.com"
```

From a documenter page, the raw collection JSON is embedded in the page state;
export via the "Run in Postman" link or copy the collection JSON blob out of
the page source. Also check GitHub/GitLab for committed
`*.postman_collection.json` / `*.postman_environment.json` files
(`filename:postman_collection.json "example.com"`) — environments often carry
live API keys. Parse with `scripts/parse_spec.py` (see
`references/postman.md`).

## 6. Well-known metadata

`/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`
yield `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
`registration_endpoint`, `introspection_endpoint`, `revocation_endpoint`,
supported grant types and algorithms. Record each as an `api:endpoint` and
hand to the auth-testing skills (dynamic client registration open? `alg:none`
accepted? `jwks_uri` on a different host?).

## 7. Brute force (last resort)

```bash
ffuf -u https://api.example.com/FUZZ -w swagger-wordlist.txt \
     -mc 200,301,302,401,403 -ac -t 40 \
     -H 'Accept: application/json' -o reports/ffuf-spec.json -of json
```

Good wordlists: SecLists `Discovery/Web-Content/swagger.txt` and
`api/api-endpoints.txt`. Also fuzz versioned doc paths:
`/swagger/FUZZ/swagger.json` with `v1..v9`, and `/v3/api-docs/FUZZ` with
group-name guesses (`admin`, `internal`, `public`, `mobile`, `partner`).

## 8. After any hit

1. Save the raw document to `reports/spec-raw.json` (convert YAML:
   `yq -o=json spec.yaml > reports/spec-raw.json`).
2. Normalize: `python3 scripts/parse_spec.py reports/spec-raw.json --base <base> -o reports/api-request-set.json`.
3. Wire into rupu per `references/rupu.md` (assets at `mapped`, work units via
   the `work-units` skill, fan out).
