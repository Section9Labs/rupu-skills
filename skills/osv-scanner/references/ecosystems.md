# OSV-Scanner v2 — ecosystem and lockfile coverage

## Lockfiles discovered by `-r` (and acceptable to `-L`)

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| PyPI | `requirements.txt` (pinned `==` lines), `Pipfile.lock`, `poetry.lock`, `pdm.lock`, `uv.lock` |
| Go | `go.mod` (plus binary scanning of Go executables via embedded buildinfo) |
| Maven | `pom.xml` (transitive resolution in v2), `buildscript-gradle.lockfile`, `gradle.lockfile`, `gradle/verification-metadata.xml` |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |
| NuGet | `packages.lock.json`, `packages.config`, `*.deps.json` |
| Packagist (Composer) | `composer.lock` |
| Pub (Dart) | `pubspec.lock` |
| Hex (Elixir) | `mix.lock` |
| CRAN (R) | `renv.lock` |
| Haskell | `cabal.project.freeze`, `stack.yaml.lock` |
| ConanCenter | `conan.lock` |
| Alpine / Debian (in images) | `apk` installed db, `dpkg` status |

Manifest-only repos (e.g. `package.json` without a lock, unpinned
`requirements.txt`) yield exit code 128 or partial inventory. Fix by
generating a lock (`npm i --package-lock-only`, `pip freeze >
requirements-frozen.txt` then `-L requirements.txt:requirements-frozen.txt`,
`go mod tidy`) or by producing an SBOM with Syft (`grype-syft` skill).

## SBOM input

SPDX (2.2/2.3, json/tag-value) and CycloneDX (1.4/1.5/1.6, json/xml) are
accepted **via `-L`**. Discovery is filename-based:

- auto-discovered: `*.spdx`, `*.spdx.json`, `*.cdx.json`, `bom.json`,
  `bom.xml`
- NOT auto-discovered: generically named files — always pass explicitly:
  `osv-scanner -L sbom-from-syft.json`

Only components with a valid `purl` are matched; SBOMs without purls
(hand-written, some legacy tools) match nothing — regenerate with Syft.

## Git / commit-based matching

OSV.dev supports version ranges by commit hash. OSV-Scanner hashes git
checkouts it finds while walking (vendored deps, submodules). The **root**
repo is skipped by default in v2 — add `--include-git-root` to match it too.

## Container images (`scan image`)

OS packages (apk/dpkg/rpm), language artifacts found in layers (jars, Go
binaries, node_modules, dist-info), with per-layer attribution. Compare
against `grype image:...` from the `grype-syft` skill for a second opinion.

## What OSV-Scanner does NOT see

- Dependencies vendored as plain source trees (no lockfile, no git metadata).
- Dynamically installed packages (Dockerfile `pip install` without a lock —
  scan the built image instead).
- CPE-only advisories that exist in NVD but not OSV.dev — Grype covers
  these; always cross-check with `grype-syft` on high-value targets.
