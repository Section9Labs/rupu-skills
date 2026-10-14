#!/usr/bin/env python3
"""Run ScoutSuite for a provider and split its results into rupu work units.

Builds the `scout <provider>` command from auth/scoping flags, runs it with
--no-browser --force, locates the freshest scoutsuite_results_*.js under the report
dir, then invokes the sibling parse_scoutsuite.py to produce out/work-units.json
(bare JSON array) and out/assets.json.

Examples:
  python3 scripts/run_scoutsuite.py aws --profile target --report-dir out/scout
  python3 scripts/run_scoutsuite.py azure --cli --subscription-ids SUB-ID-1
  python3 scripts/run_scoutsuite.py gcp --service-account sa.json --all-projects
  python3 scripts/run_scoutsuite.py aws --skip-run --report-dir out/scout  # reparse only
"""
import argparse
import glob
import os
import subprocess
import sys


def newest_results(report_dir):
    pats = [
        os.path.join(report_dir, "scoutsuite-results", "scoutsuite_results_*.js"),
        os.path.join(report_dir, "**", "scoutsuite_results_*.js"),
    ]
    candidates = []
    for pat in pats:
        candidates += glob.glob(pat, recursive=True)
    if not candidates:
        return None
    return max(set(candidates), key=os.path.getmtime)


def build_cmd(args):
    cmd = ["scout", args.provider]

    # --- AWS auth ---
    if args.profile:
        cmd += ["--profile", args.profile]
    if args.access_key_id:
        cmd += ["--access-keys", "--access-key-id", args.access_key_id,
                "--secret-access-key", args.secret_access_key or ""]
        if args.session_token:
            cmd += ["--session-token", args.session_token]

    # --- Azure auth ---
    if args.cli:
        cmd += ["--cli"]
    if args.user_account:
        cmd += ["--user-account"]
    if args.msi:
        cmd += ["--msi"]
    if args.service_principal:
        cmd += ["--service-principal"]
        if args.tenant_id:
            cmd += ["--tenant-id", args.tenant_id]
        if args.client_id:
            cmd += ["--client-id", args.client_id]
        if args.client_secret:
            cmd += ["--client-secret", args.client_secret]
    if args.subscription_ids:
        cmd += ["--subscription-ids"] + args.subscription_ids
    if args.all_subscriptions:
        cmd += ["--all-subscriptions"]

    # --- GCP auth / scope ---
    if args.service_account:
        cmd += ["--service-account", args.service_account]
    if args.project_id:
        cmd += ["--project-id", args.project_id]
    if args.all_projects:
        cmd += ["--all-projects"]
    if args.organization_id:
        cmd += ["--organization-id", args.organization_id]
    if args.folder_id:
        cmd += ["--folder-id", args.folder_id]

    # --- scoping / tuning ---
    if args.regions:
        cmd += ["--regions"] + args.regions
    if args.services:
        cmd += ["--services"] + args.services
    if args.skip_services:
        cmd += ["--skip-services"] + args.skip_services
    if args.ruleset:
        cmd += ["--ruleset", args.ruleset]
    if args.max_rate:
        cmd += ["--max-rate", str(args.max_rate)]
    if args.max_workers:
        cmd += ["--max-workers", str(args.max_workers)]

    cmd += ["--report-dir", args.report_dir, "--no-browser", "--force"]
    if args.report_name:
        cmd += ["--report-name", args.report_name]
    if args.extra:
        cmd += args.extra
    return cmd


def main():
    p = argparse.ArgumentParser(
        description="Run ScoutSuite and emit rupu work units from its results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("provider", choices=["aws", "azure", "gcp", "aliyun", "oci"],
                   help="scout provider subcommand")
    # AWS
    p.add_argument("--profile", help="AWS named profile")
    p.add_argument("--access-key-id", help="AWS access key (with --secret-access-key)")
    p.add_argument("--secret-access-key")
    p.add_argument("--session-token")
    # Azure
    p.add_argument("--cli", action="store_true", help="reuse `az login` session")
    p.add_argument("--user-account", action="store_true", help="interactive user login")
    p.add_argument("--msi", action="store_true", help="Azure managed identity")
    p.add_argument("--service-principal", action="store_true",
                   help="SP auth; combine with --tenant-id/--client-id/--client-secret")
    p.add_argument("--tenant-id")
    p.add_argument("--client-id")
    p.add_argument("--client-secret")
    p.add_argument("--subscription-ids", nargs="+")
    p.add_argument("--all-subscriptions", action="store_true")
    # GCP
    p.add_argument("--service-account", help="GCP SA key JSON path")
    p.add_argument("--project-id")
    p.add_argument("--all-projects", action="store_true")
    p.add_argument("--organization-id")
    p.add_argument("--folder-id")
    # Scoping / tuning
    p.add_argument("--regions", nargs="+")
    p.add_argument("--services", nargs="+")
    p.add_argument("--skip-services", nargs="+")
    p.add_argument("--ruleset", help="custom ruleset JSON")
    p.add_argument("--max-rate", type=int, help="API requests/sec cap")
    p.add_argument("--max-workers", type=int, help="concurrent API threads")
    # Output / control
    p.add_argument("--report-dir", default="out/scout")
    p.add_argument("--report-name", help="report filename stem")
    p.add_argument("--out", default="out/work-units.json", help="work-units array path")
    p.add_argument("--assets-out", default="out/assets.json", help="assets array path")
    p.add_argument("--skip-run", action="store_true",
                   help="do not run scout; reparse newest results js in --report-dir")
    p.add_argument("--no-parse", action="store_true", help="run scout only, skip parsing")
    p.add_argument("--all-warnings", action="store_true",
                   help="pass --all-warnings to the parser")
    p.add_argument("--dangers-only", action="store_true",
                   help="pass --dangers-only to the parser")
    p.add_argument("--extra", nargs=argparse.REMAINDER,
                   help="raw extra args appended to the scout command")
    args = p.parse_args()

    os.makedirs(args.report_dir, exist_ok=True)

    if not args.skip_run:
        cmd = build_cmd(args)
        shown = [a if a != (args.client_secret or object()) else "***" for a in cmd]
        print("[*] exec: " + " ".join(shown), file=sys.stderr)
        rc = subprocess.call(cmd)
        if rc != 0:
            print("[!] scout exited %d — rerun with --extra --debug for detail" % rc,
                  file=sys.stderr)
            # keep going: a partial inventory still parses

    results = newest_results(args.report_dir)
    if not results:
        print("[!] no scoutsuite_results_*.js under %s" % args.report_dir, file=sys.stderr)
        sys.exit(1)
    print("[*] results: %s" % results, file=sys.stderr)

    if args.no_parse:
        print(results)
        return

    parser_script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "parse_scoutsuite.py")
    pcmd = [sys.executable, parser_script, "--input", results,
            "--out", args.out, "--assets-out", args.assets_out]
    if args.all_warnings:
        pcmd.append("--all-warnings")
    if args.dangers_only:
        pcmd.append("--dangers-only")
    sys.exit(subprocess.call(pcmd))


if __name__ == "__main__":
    main()
