#!/usr/bin/env python3
"""profile_repo.py — PHASE 0 repository profiler for the code-review umbrella skill.

Walks a source tree and emits a repo-profile JSON:
  {
    "repo": "<path>",
    "languages":   [{"lang": "...", "files": N, "loc_est": N}, ...],
    "manifests":   [{"path": "...", "ecosystem": "...", "kind": "manifest|lockfile|build"}, ...],
    "ecosystems":  ["python", "npm", ...],
    "entry_points":[{"path": "...", "reasons": ["http-route", ...]}, ...],
    "suggested_tools": ["semgrep", "bandit", ...]
  }

Usage:
  python3 scripts/profile_repo.py /path/to/repo -o repo-profile.json
  python3 scripts/profile_repo.py .                      # print to stdout

Stdlib only. The output feeds scripts/plan_review.py.
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".idea", ".vscode", "bower_components", ".terraform", ".gradle",
}

EXT_LANG = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby", ".erb": "ruby",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".rs": "rust",
    ".php": "php", ".phtml": "php",
    ".cs": "csharp",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".m": "objective-c",
    ".sh": "shell", ".bash": "shell",
    ".sql": "sql",
    ".tf": "terraform", ".yaml": "yaml", ".yml": "yaml",
    ".html": "html", ".vue": "javascript", ".svelte": "javascript",
}

# filename (exact or glob-ish) -> (ecosystem, kind)
MANIFESTS = {
    "requirements.txt": ("python", "manifest"),
    "requirements-dev.txt": ("python", "manifest"),
    "setup.py": ("python", "manifest"),
    "setup.cfg": ("python", "manifest"),
    "pyproject.toml": ("python", "manifest"),
    "Pipfile": ("python", "manifest"),
    "Pipfile.lock": ("python", "lockfile"),
    "poetry.lock": ("python", "lockfile"),
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "go.mod": ("go", "manifest"),
    "go.sum": ("go", "lockfile"),
    "pom.xml": ("maven", "build"),
    "build.gradle": ("gradle", "build"),
    "build.gradle.kts": ("gradle", "build"),
    "settings.gradle": ("gradle", "build"),
    "Gemfile": ("rubygems", "manifest"),
    "Gemfile.lock": ("rubygems", "lockfile"),
    "Cargo.toml": ("cargo", "manifest"),
    "Cargo.lock": ("cargo", "lockfile"),
    "composer.json": ("composer", "manifest"),
    "composer.lock": ("composer", "lockfile"),
    "Dockerfile": ("docker", "build"),
    "Makefile": ("make", "build"),
}

ENTRY_NAME_HINTS = [
    (re.compile(r"(^|/)(main|app|server|index|wsgi|asgi|manage)\.(py|js|ts|go|rb)$"), "main"),
    (re.compile(r"(routes?|urls?|views?|handlers?|controllers?|endpoints?|api)", re.I), "route-file-name"),
    (re.compile(r"(auth|login|session|oauth|jwt|token|password)", re.I), "auth-file-name"),
    (re.compile(r"(upload|import|parser)", re.I), "input-handling-name"),
]

# content heuristics: (regex, reason) — checked against first 64 KiB of text files
ENTRY_CONTENT_HINTS = [
    (re.compile(r"@(app|router|api|bp|blueprint)\.(get|post|put|delete|patch|route)\b"), "http-route"),
    (re.compile(r"\b(app|router)\.(get|post|put|delete|patch|use)\s*\(\s*['\"]/"), "http-route"),
    (re.compile(r"\bhttp\.HandleFunc\b|\bmux\.(Handle|HandleFunc)\b|\b(gin|echo|chi|fiber)\.\w+"), "http-route"),
    (re.compile(r"@(Get|Post|Put|Delete|Request)Mapping\b|@Path\s*\("), "http-route"),
    (re.compile(r"\bif\s+__name__\s*==\s*['\"]__main__['\"]"), "cli-main"),
    (re.compile(r"\bfunc\s+main\s*\(\s*\)"), "cli-main"),
    (re.compile(r"\b(pickle|cPickle)\.loads?\b|\byaml\.(load|unsafe_load)\b|\bmarshal\.loads\b"), "deserialization"),
    (re.compile(r"\bObjectInputStream\b|\breadObject\s*\(|\bXMLDecoder\b"), "deserialization"),
    (re.compile(r"\bMarshal\.load\b|\bunserialize\s*\("), "deserialization"),
    (re.compile(r"\brender_template_string\b|\bTemplate\s*\(.*\+|\bnew\s+Function\s*\(|\bejs\.render\b"), "templating"),
    (re.compile(r"\b(execute|exec|query|raw)\s*\(\s*(f?['\"].*(SELECT|INSERT|UPDATE|DELETE)|.*%s.*\+)", re.I), "raw-sql"),
    (re.compile(r"\b(os\.system|subprocess\.(call|run|Popen)|exec\.Command|Runtime\.getRuntime\(\)\.exec|child_process|popen|proc_open|shell_exec)\b"), "command-exec"),
    (re.compile(r"\b(authenticate|authorize|login|check_password|verify_token|jwt\.(decode|verify))\b", re.I), "auth-logic"),
    (re.compile(r"(api[_-]?key|secret[_-]?key|password|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)", re.I), "possible-secret"),
]

LANG_TOOLS = {
    "python": ["bandit"],
    "go": ["gosec"],
    "ruby": ["brakeman"],
    "javascript": ["njsscan", "retire-js"],
    "typescript": ["njsscan", "retire-js"],
    "java": ["find-sec-bugs", "codeql"],
    "kotlin": ["find-sec-bugs"],
    "csharp": ["codeql"],
    "c": ["codeql"],
    "cpp": ["codeql"],
    "rust": [],
    "php": [],
}

ECO_TOOLS = {
    "python": ["osv-scanner", "grype-syft"],
    "npm": ["osv-scanner", "grype-syft", "retire-js"],
    "go": ["osv-scanner", "grype-syft"],
    "maven": ["dependency-check", "osv-scanner", "grype-syft"],
    "gradle": ["dependency-check", "osv-scanner", "grype-syft"],
    "rubygems": ["osv-scanner", "grype-syft"],
    "cargo": ["cargo-audit", "osv-scanner"],
    "composer": ["osv-scanner", "grype-syft"],
    "nuget": ["dependency-check", "grype-syft"],
    "docker": ["grype-syft"],
}


def est_loc(path):
    """Count non-blank lines; cheap LOC estimate."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        if b"\x00" in data[:8192]:
            return 0
        return sum(1 for ln in data.splitlines() if ln.strip())
    except OSError:
        return 0


def profile(root):
    langs = {}
    manifests = []
    entry_points = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")

            # manifests
            if fn in MANIFESTS:
                eco, kind = MANIFESTS[fn]
                manifests.append({"path": rel, "ecosystem": eco, "kind": kind})
            elif fn.endswith(".csproj"):
                manifests.append({"path": rel, "ecosystem": "nuget", "kind": "build"})

            # language census
            ext = os.path.splitext(fn)[1].lower()
            lang = EXT_LANG.get(ext)
            if lang:
                st = langs.setdefault(lang, {"files": 0, "loc_est": 0})
                st["files"] += 1
                st["loc_est"] += est_loc(full)

            # entry-point name heuristics
            reasons = set()
            for rx, reason in ENTRY_NAME_HINTS:
                if rx.search(rel):
                    reasons.add(reason)

            # entry-point content heuristics (code files only)
            if lang and lang not in ("yaml", "html", "sql"):
                try:
                    with open(full, "rb") as f:
                        head = f.read(65536)
                    if b"\x00" not in head:
                        text = head.decode("utf-8", errors="replace")
                        for rx, reason in ENTRY_CONTENT_HINTS:
                            if rx.search(text):
                                reasons.add(reason)
                except OSError:
                    pass

            if reasons:
                entry_points[rel] = sorted(reasons)

    ecosystems = sorted({m["ecosystem"] for m in manifests})

    suggested = ["semgrep", "gitleaks", "trufflehog", "taint-analysis"]
    for lang in langs:
        for t in LANG_TOOLS.get(lang, []):
            if t not in suggested:
                suggested.append(t)
    for eco in ecosystems:
        for t in ECO_TOOLS.get(eco, []):
            if t not in suggested:
                suggested.append(t)
    # codeql for any compiled/high-value language present
    if any(l in langs for l in ("java", "csharp", "c", "cpp", "go", "javascript", "typescript", "python", "ruby")):
        if "codeql" not in suggested:
            suggested.append("codeql")

    return {
        "repo": os.path.abspath(root),
        "languages": sorted(
            ({"lang": k, **v} for k, v in langs.items()),
            key=lambda x: -x["loc_est"],
        ),
        "manifests": sorted(manifests, key=lambda m: m["path"]),
        "ecosystems": ecosystems,
        "entry_points": [
            {"path": p, "reasons": r} for p, r in sorted(entry_points.items())
        ],
        "suggested_tools": suggested,
    }


def main():
    ap = argparse.ArgumentParser(description="Profile a repository for security code review (PHASE 0).")
    ap.add_argument("repo", help="path to the source tree")
    ap.add_argument("-o", "--output", help="write JSON here (default: stdout)")
    args = ap.parse_args()

    if not os.path.isdir(args.repo):
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        sys.exit(2)

    prof = profile(args.repo)
    out = json.dumps(prof, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print(
            f"wrote {args.output}: {len(prof['languages'])} languages, "
            f"{len(prof['manifests'])} manifests, {len(prof['entry_points'])} entry points, "
            f"tools: {', '.join(prof['suggested_tools'])}",
            file=sys.stderr,
        )
    else:
        print(out)


if __name__ == "__main__":
    main()
