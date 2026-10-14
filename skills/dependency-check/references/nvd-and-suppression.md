# NVD API key, data cache, and the suppression file

## NVD API key

The NVD 2.0 API throttles anonymous clients to ~5 requests / 30s; with a key
it's ~50 / 30s. The initial database build pulls the entire CVE corpus — hours
without a key, and frequently fails with 403/429. **Always use a key.**

1. Request a key at https://nvd.nist.gov/developers/request-an-api-key
   (free, instant email confirmation).
2. Export it and pass it:

```bash
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
dependency-check.sh --nvdApiKey "$NVD_API_KEY" --updateonly --data /opt/odc-data
```

Tuning when you still get throttled:

```bash
--nvdApiDelay 6000        # ms between page requests (default ~2000 w/o key)
--nvdMaxRetryCount 20
--nvdValidForHours 24     # don't re-check NVD more than daily
```

Air-gapped / fleet mirror: host the pre-generated feed cache and point
`--nvdDatafeed https://198.51.100.10/nvdcache/` (optionally
`--nvdUser/--nvdPassword`), or share one H2 cache dir, or run a central
PostgreSQL/MySQL via `--connectionString/--dbUser/--dbPassword` with one
writer doing `--updateonly` and all scanners read-only.

## Data cache lifecycle

- Default location: `<install>/data/` (Docker image:
  `/usr/share/dependency-check/data`). Override: `--data /opt/odc-data`.
- Contents: H2 database (`odc.mv.db`) with NVD CVEs + CPE index, plus cached
  RetireJS repo, KEV JSON, hosted-suppressions file.
- **Nightly**: `--updateonly --nvdApiKey ...` on the shared cache.
- **Per scan**: `--noupdate --data /opt/odc-data` → fast, deterministic,
  no network needed (except NPM Audit / OSS Index API analyzers, which call
  out at scan time — disable them for fully offline runs).
- A killed update can leave `odc.update.lock` or a corrupt DB:
  `dependency-check.sh --purge --data /opt/odc-data` then re-update.

## Other credentialed sources

- **OSS Index**: anonymous works but rate-limits aggressively on big trees.
  Free account at ossindex.sonatype.org →
  `--ossIndexUsername user@example.com --ossIndexPassword <token>`.
  `--ossIndexRemoteErrorWarnOnly` keeps the scan alive when OSS Index 429s.
- **NPM Audit** needs network + `package-lock.json`; no credentials.
- **KEV**: public JSON, auto-downloaded; mirror with `--kevURL`.

## Suppression file

Pass with `--suppression suppressions.xml` (repeatable; URL or path).
Schema: `https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd`.

Structure of a `<suppress>` entry — one *selector* (what dependency) plus one
or more *targets* (what to suppress on it):

Selectors (pick one):
- `<sha1>` — exact artifact hash. Most precise; survives renames.
- `<packageUrl [regex="true"]>` — purl match, e.g.
  `^pkg:maven/com\.example/.*@.*$`. Best for lockfile/virtual deps.
- `<filePath [regex="true"]>` — path match, e.g. `.*\btest\b.*\.jar`.
- `<gav [regex="true"]>` — legacy Maven group:artifact:version.

Targets (repeatable):
- `<cpe>` — kill a wrong CPE match entirely (removes ALL CVEs that came from
  it). Prefix match: `cpe:/a:apache:commons_fileupload`.
- `<cve>` — suppress one specific CVE.
- `<vulnerabilityName [regex="true"]>` — for non-CVE ids (OSS Index
  `CVE-...`/`sonatype-...` ids, GHSA ids, RetireJS names).
- `<cvssBelow>` — suppress anything under a CVSS score.

Attributes: `base="true"` (hide from report entirely rather than listing as
suppressed), `until="2026-06-30Z"` (expiry — forces periodic re-review).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">

  <!-- Wrong CPE: internal artifact misidentified as Apache product -->
  <suppress>
    <notes>example-utils.jar is in-house, not apache:commons. Verified via jar manifest. -vulture/cobalt-mill</notes>
    <sha1>384faa82e193d4e4b0546059ca09572654bc3970</sha1>
    <cpe>cpe:/a:apache:commons_fileupload</cpe>
  </suppress>

  <!-- One CVE not applicable (server-only vuln, we ship the client lib) -->
  <suppress until="2026-06-30Z">
    <notes>CVE applies to server component; client lib unaffected per advisory.</notes>
    <packageUrl regex="true">^pkg:maven/org\.example/example-client@.*$</packageUrl>
    <cve>CVE-2023-12345</cve>
  </suppress>

  <!-- Test fixtures: suppress everything under a path -->
  <suppress>
    <notes>Deliberately vulnerable test fixtures, not shipped.</notes>
    <filePath regex="true">.*/src/test/resources/.*</filePath>
    <cvssBelow>10</cvssBelow>
  </suppress>

  <!-- Non-CVE id from OSS Index / GHSA -->
  <suppress>
    <notes>Dev-only tooling.</notes>
    <packageUrl regex="true">^pkg:npm/example\-cli@.*$</packageUrl>
    <vulnerabilityName regex="true">^GHSA-.*$</vulnerabilityName>
  </suppress>

</suppressions>
```

Workflow tips:
- The **HTML report "suppress" button** on each finding emits a ready-made
  `<suppress>` block — copy it, add `<notes>` explaining WHY, commit the file
  to the repo so suppressions are reviewed like code.
- Suppressing a **CPE** on a wrong-match kills current and future CVEs from
  that CPE; suppressing a **CVE** only kills one. Use `<cpe>` for
  misidentification, `<cve>` for not-applicable.
- For systematic misidentification, prefer a **hints file** (`--hints`) that
  adds/removes evidence so the match is corrected, not just hidden.
- ODC also auto-applies a hosted "base suppression" file of community-known
  FPs (`--hostedSuppressionsUrl` to mirror, `--disableHostedSuppressions` to
  turn off).

## Confirming a suspected false positive

1. Open the dependency in the HTML report → **Evidence** tab. See which
   evidence string (filename? manifest vendor? pom groupId?) drove the CPE,
   and its confidence.
2. Compare the CPE vendor:product to the purl / `META-INF/MANIFEST.MF` /
   `pom.properties` inside the jar (`unzip -p lib.jar META-INF/maven/*/*/pom.properties`).
3. Check `vulnerableSoftware` ranges in the JSON against the real version.
4. If CPE is right and version is in range → true positive; move to
   reachability + exploitation. Otherwise write the suppression with notes.
