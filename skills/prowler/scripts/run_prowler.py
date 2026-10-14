#!/usr/bin/env python3
"""Run Prowler for a provider and split its OCSF output into rupu work units.

Builds the prowler command line from provider-specific auth/scoping flags, runs it,
locates the freshest *.ocsf.json in the output directory, then invokes the sibling
parse_prowler.py to produce out/work-units.json (bare JSON array) and out/assets.json.

Examples:
  python3 scripts/run_prowler.py aws --profile target -f us-east-1 eu-west-1 \
      --severity critical high
  python3 scripts/run_prowler.py azure --az-cli-auth --subscription-ids SUB-ID-1
  python3 scripts/run_prowler.py gcp --credentials-file sa.json --project-ids proj-example-1
  python3 scripts/run_prowler.py kubernetes --kubeconfig-file ~/.kube/config
  python3 scripts/run_prowler.py aws --skip-run --output-dir out/prowler   # reparse only
"""
import argparse
import glob
import os
import subprocess
import sys


def newest_ocsf(output_dir):
    candidates = glob.glob(os.path.join(output_dir, "**", "*.ocsf.json"), recursive=True)
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def build_cmd(args):
    cmd = ["prowler", args.provider]

    # --- AWS auth / scope ---
    if args.profile:
        cmd += ["--profile", args.profile]
    if args.role:
        cmd += ["--role", args.role]
        if args.session_duration:
            cmd += ["--session-duration", str(args.session_duration)]
    if args.regions:
        cmd += ["-f"] + args.regions

    # --- Azure auth / scope (pick ONE auth flag) ---
    if args.az_cli_auth:
        cmd += ["--az-cli-auth"]
    if args.sp_env_auth:
        cmd += ["--sp-env-auth"]
    if args.browser_auth:
        cmd += ["--browser-auth"]
    if args.managed_identity_auth:
        cmd += ["--managed-identity-auth"]
    if args.tenant_id:
        cmd += ["--tenant-id", args.tenant_id]
    if args.subscription_ids:
        cmd += ["--subscription-ids"] + args.subscription_ids

    # --- GCP auth / scope ---
    if args.credentials_file:
        cmd += ["--credentials-file", args.credentials_file]
    if args.project_ids:
        cmd += ["--project-ids"] + args.project_ids
    if args.impersonate_service_account:
        cmd += ["--impersonate-service-account", args.impersonate_service_account]

    # --- Kubernetes ---
    if args.kubeconfig_file:
        cmd += ["--kubeconfig-file", args.kubeconfig_file]
    if args.context:
        cmd += ["--context", args.context]
    if args.namespace:
        cmd += ["--namespace"] + args.namespace

    # --- scan scoping ---
    if args.severity:
        cmd += ["--severity"] + args.severity
    if args.services:
        cmd += ["--services"] + args.services
    if args.checks:
        cmd += ["--checks"] + args.checks
    if args.compliance:
        cmd += ["--compliance", args.compliance]
    if args.categories:
        cmd += ["--categories"] + args.categories
    if args.excluded_services:
        cmd += ["--excluded-services"] + args.excluded_services
    if args.fail_only:
        cmd += ["--status", "FAIL"]

    # --- output ---
    cmd += ["--output-formats", "csv", "json-ocsf", "html",
            "--output-directory", args.output_dir]
    if args.output_filename:
        cmd += ["--output-filename", args.output_filename]

    if args.extra:
        cmd += args.extra
    return cmd


def main():
    p = argparse.ArgumentParser(
        description="Run prowler and emit rupu work units from its OCSF output.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("provider", choices=["aws", "azure", "gcp", "kubernetes"],
                   help="prowler provider subcommand")
    # AWS
    p.add_argument("--profile", help="AWS named profile")
    p.add_argument("--role", help="role ARN to assume (arn:aws:iam::123456789012:role/...)")
    p.add_argument("--session-duration", type=int, help="assumed-role session seconds")
    p.add_argument("-f", "--regions", nargs="+", help="AWS region scope")
    # Azure (choose one auth flag)
    p.add_argument("--az-cli-auth", action="store_true", help="reuse `az login` session")
    p.add_argument("--sp-env-auth", action="store_true",
                   help="service principal from AZURE_CLIENT_ID/SECRET/TENANT_ID env")
    p.add_argument("--browser-auth", action="store_true", help="interactive browser auth")
    p.add_argument("--managed-identity-auth", action="store_true", help="Azure managed identity")
    p.add_argument("--tenant-id", help="Azure tenant id (required with --browser-auth)")
    p.add_argument("--subscription-ids", nargs="+", help="Azure subscription scope")
    # GCP
    p.add_argument("--credentials-file", help="GCP service-account key JSON")
    p.add_argument("--project-ids", nargs="+", help="GCP project scope")
    p.add_argument("--impersonate-service-account", help="GCP SA to impersonate")
    # Kubernetes
    p.add_argument("--kubeconfig-file", help="kubeconfig path")
    p.add_argument("--context", help="kubeconfig context")
    p.add_argument("--namespace", nargs="+", help="namespace scope")
    # Scoping
    p.add_argument("--severity", nargs="+",
                   choices=["critical", "high", "medium", "low", "informational"])
    p.add_argument("--services", nargs="+", help="service scope, e.g. s3 iam ec2")
    p.add_argument("--checks", nargs="+", help="specific check ids")
    p.add_argument("--compliance", help="framework, e.g. cis_2.0_aws")
    p.add_argument("--categories", nargs="+", help="e.g. internet-exposed")
    p.add_argument("--excluded-services", nargs="+")
    p.add_argument("--fail-only", action="store_true", help="pass --status FAIL to prowler")
    # Output / control
    p.add_argument("--output-dir", default="out/prowler", help="prowler --output-directory")
    p.add_argument("--output-filename", help="prowler --output-filename")
    p.add_argument("--out", default="out/work-units.json", help="work-units JSON array path")
    p.add_argument("--assets-out", default="out/assets.json", help="assets JSON array path")
    p.add_argument("--skip-run", action="store_true",
                   help="do not run prowler; reparse newest existing OCSF in --output-dir")
    p.add_argument("--no-parse", action="store_true", help="run prowler only, skip parsing")
    p.add_argument("--all-fails", action="store_true",
                   help="pass --all-fails to the parser (keep every FAIL)")
    p.add_argument("--extra", nargs=argparse.REMAINDER,
                   help="raw extra args appended to the prowler command")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    if not args.skip_run:
        cmd = build_cmd(args)
        print("[*] exec: " + " ".join(cmd), file=sys.stderr)
        rc = subprocess.call(cmd)
        # exit 0 = no findings, 3 = findings exist (success for us)
        if rc not in (0, 3):
            print("[!] prowler exited %d (runtime error) — check --log-level DEBUG" % rc,
                  file=sys.stderr)
            sys.exit(rc)
        if rc == 3:
            print("[+] prowler exit 3: FAIL findings exist", file=sys.stderr)

    ocsf = newest_ocsf(args.output_dir)
    if not ocsf:
        print("[!] no *.ocsf.json found under %s" % args.output_dir, file=sys.stderr)
        sys.exit(1)
    print("[*] OCSF output: %s" % ocsf, file=sys.stderr)

    if args.no_parse:
        print(ocsf)
        return

    parser_script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "parse_prowler.py")
    pcmd = [sys.executable, parser_script, "--input", ocsf,
            "--out", args.out, "--assets-out", args.assets_out]
    if args.all_fails:
        pcmd.append("--all-fails")
    sys.exit(subprocess.call(pcmd))


if __name__ == "__main__":
    main()
