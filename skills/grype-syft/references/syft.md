# Syft reference — sources, formats, cataloging

## Sources

| Scheme | Meaning |
|---|---|
| `dir:<path>` | Filesystem directory (source tree, extracted rootfs). `syft dir:.` |
| `file:<path>` | Single file: archive (recurses into nested jars/zips/tars), binary, or package file. |
| `image:<ref>` / bare `<ref>` | Container image. Resolution order (configurable with `--from`): docker daemon, podman, containerd, then registry. `syft nginx:latest` |
| `registry:<ref>` | Force direct registry pull, no daemon required. `syft registry:example.com/app:1.4` |
| `docker-archive:<tar>` | `docker save` tarball. |
| `oci-archive:<tar>` / `oci-dir:<dir>` | OCI layout. |
| `singularity:<sif>` | Singularity image. |

Pull creds for private registries: `SYFT_REGISTRY_AUTH_USERNAME` /
`SYFT_REGISTRY_AUTH_PASSWORD` / `SYFT_REGISTRY_AUTH_TOKEN`, or docker config.

## Output formats (`-o <format>[=<file>]`, repeatable)

| Format | Use |
|---|---|
| `syft-json` | Native, lossless. **Best input for Grype** (`sbom:` source). |
| `cyclonedx-json`, `cyclonedx-xml` | Interchange; accepted by osv-scanner `-L`, dependency-track, etc. Add `@1.5`/`@1.6` to pin spec version: `-o cyclonedx-json@1.5=sbom.cdx.json`. |
| `spdx-json`, `spdx-tag-value` | SPDX interchange (`@2.2`/`@2.3`). |
| `table` | Human-readable summary (default to stdout). |
| `text` | Minimal listing. |
| `template` | Go template via `-t template.tmpl`. |

Emit several at once: `syft dir:. -o syft-json=sbom.json -o cyclonedx-json=sbom.cdx.json -o table`.

## Scope (image sources)

- `--scope squashed` (default) — final merged filesystem only.
- `--scope all-layers` — catalog every layer; finds packages installed then
  deleted in later layers (build tools, temporary pip installs) that still
  ship in layer blobs. Use for security review of images.

## Cataloger selection

Default cataloger set depends on source type (image vs directory).
Tune with:

- `--select-catalogers "python,javascript"` — restrict to tag/name subsets.
- `--select-catalogers "+sbom-cataloger"` — add a cataloger to the defaults
  (sbom-cataloger ingests SBOMs already present in the target).
- `--override-default-catalogers "go-module-binary-cataloger"` — replace the
  set entirely.
- `syft cataloger list` — enumerate available catalogers and their tags.

Catalogers cover: apk, dpkg, rpm; npm/yarn/pnpm, Python (dist-info, poetry,
pip requirements), Go modules + Go binary buildinfo, Java archives
(jar/war/ear, nested), Gradle/Maven, Ruby gemspec/Gemfile.lock, Rust
Cargo.lock + audit binaries, PHP composer, .NET deps.json + PE metadata,
Swift, Dart, Haskell, Erlang/Elixir, Conan, generic binary classifiers
(busybox, node, python interpreters…).

## Other useful flags

| Flag | Meaning |
|---|---|
| `--exclude './node_modules/**'` | Glob-exclude paths (repeatable). |
| `--source-name` / `--source-version` | Stamp SBOM subject metadata. |
| `--platform linux/arm64` | Select arch for multi-arch image refs. |
| `--enrich all` | Network enrichment (e.g. Maven parent POM license lookup). |
| `-q` / `-v` / `-vv` | Quiet / verbose logging. |
| `syft convert sbom.json -o spdx-json=sbom.spdx.json` | Convert between SBOM formats without re-scanning. |
| `syft attest` | Generate a signed in-toto SBOM attestation for an image (cosign keys). |

## syft-json shape (what downstream reads)

```json
{"artifacts": [
   {"name": "lodash", "version": "4.17.20", "type": "npm",
    "purl": "pkg:npm/lodash@4.17.20",
    "locations": [{"path": "package-lock.json"}],
    "licenses": [...], "metadata": {...}}],
 "source": {"type": "directory", "target": "/work/example-repo"},
 "distro": {"name": "alpine", "version": "3.18"}}
```

`artifacts[]` is the coverage ledger: every entry becomes a package asset in
`assets.mark` (see `references/rupu.md`), whether or not Grype flags it.
