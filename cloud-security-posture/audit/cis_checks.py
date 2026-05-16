#!/usr/bin/env python3
"""
audit/cis_checks.py

Read-only CIS AWS Foundations Benchmark v1.5 checks.
Requires: boto3, rich  (pip install boto3 rich)

Usage:
    python cis_checks.py --profile myprofile --region us-east-1
    python cis_checks.py --region us-east-1          # uses default credential chain
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

import boto3
from rich.console import Console
from rich.table import Table

console = Console()

Status = Literal["PASS", "FAIL", "WARN", "SKIP"]


@dataclass
class Finding:
    control_id: str
    title: str
    status: Status
    detail: str = ""
    remediation: str = ""


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def passed(self) -> int:
        return sum(1 for f in self.findings if f.status == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for f in self.findings if f.status == "FAIL")


# ---------------------------------------------------------------------------
# CIS checks
# ---------------------------------------------------------------------------

def check_root_mfa(iam) -> Finding:
    """CIS 1.5 — Ensure MFA is enabled for the root account."""
    summary = iam.get_account_summary()["SummaryMap"]
    mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
    return Finding(
        control_id="1.5",
        title="Root account MFA enabled",
        status="PASS" if mfa_enabled else "FAIL",
        detail="Root MFA is active." if mfa_enabled else "Root account has NO MFA — critical risk.",
        remediation="Enable MFA on the root account via IAM console → Security credentials.",
    )


def check_no_root_access_keys(iam) -> Finding:
    """CIS 1.4 — Ensure no root account access keys exist."""
    summary = iam.get_account_summary()["SummaryMap"]
    has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
    return Finding(
        control_id="1.4",
        title="No root access keys",
        status="FAIL" if has_keys else "PASS",
        detail="Root access keys exist — delete immediately." if has_keys else "No root access keys found.",
        remediation="Delete root access keys from IAM → Security credentials.",
    )


def check_password_policy(iam) -> Finding:
    """CIS 1.8-1.11 — Password policy minimum requirements."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("minimum length < 14")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("no uppercase requirement")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("no lowercase requirement")
        if not policy.get("RequireNumbers"):
            issues.append("no number requirement")
        if not policy.get("RequireSymbols"):
            issues.append("no symbol requirement")
        if not policy.get("ExpirePasswords"):
            issues.append("passwords do not expire")
        if policy.get("PasswordReusePrevention", 0) < 24:
            issues.append("password reuse prevention < 24")

        status: Status = "FAIL" if issues else "PASS"
        detail = f"Issues: {', '.join(issues)}" if issues else "Password policy meets CIS requirements."
        return Finding("1.8-1.11", "IAM password policy", status, detail,
                       "Update password policy in IAM console to meet all CIS requirements.")
    except iam.exceptions.NoSuchEntityException:
        return Finding("1.8-1.11", "IAM password policy", "FAIL",
                       "No password policy is set.",
                       "Configure a password policy in IAM.")


def check_cloudtrail_enabled(cloudtrail) -> Finding:
    """CIS 3.1 — Ensure CloudTrail is enabled in all regions."""
    trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    status: Status = "PASS" if multi_region else "FAIL"
    detail = (
        f"{len(multi_region)} multi-region trail(s) active."
        if multi_region
        else "No multi-region CloudTrail found."
    )
    return Finding(
        "3.1", "CloudTrail multi-region enabled", status, detail,
        "Enable CloudTrail in all regions from the CloudTrail console.",
    )


def check_cloudtrail_log_validation(cloudtrail) -> Finding:
    """CIS 3.2 — Ensure CloudTrail log file validation is enabled."""
    trails = cloudtrail.describe_trails().get("trailList", [])
    bad = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
    status: Status = "FAIL" if bad else "PASS"
    detail = f"Trails without validation: {bad}" if bad else "All trails have log file validation enabled."
    return Finding(
        "3.2", "CloudTrail log file validation", status, detail,
        "Enable log file validation on all CloudTrail trails.",
    )


def check_s3_public_access(s3_control, account_id) -> Finding:
    """CIS 2.1.5 — S3 account-level public access block."""
    try:
        cfg = s3_control.get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
        all_blocked = all([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
        status: Status = "PASS" if all_blocked else "FAIL"
        detail = "All four S3 account public access block settings are enabled." if all_blocked else str(cfg)
        return Finding(
            "2.1.5", "S3 account public access block", status, detail,
            "Enable all four settings in S3 → Block Public Access (account settings).",
        )
    except Exception as exc:
        return Finding("2.1.5", "S3 account public access block", "FAIL",
                       f"Could not retrieve setting: {exc}")


def check_guardduty(guardduty, region) -> Finding:
    """CIS 3.9 — Ensure GuardDuty is enabled."""
    detectors = guardduty.list_detectors().get("DetectorIds", [])
    if not detectors:
        return Finding("3.9", "GuardDuty enabled", "FAIL",
                       f"No GuardDuty detector in {region}.",
                       "Enable GuardDuty in the GuardDuty console.")
    detail = guardduty.get_detector(DetectorId=detectors[0])
    status: Status = "PASS" if detail.get("Status") == "ENABLED" else "FAIL"
    return Finding(
        "3.9", "GuardDuty enabled", status,
        f"Detector {detectors[0]}: {detail.get('Status')}",
        "Enable GuardDuty if it is not already active.",
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_table(result: AuditResult) -> None:
    table = Table(title="CIS AWS Foundations Benchmark Audit", show_lines=True)
    table.add_column("Control", style="dim", width=10)
    table.add_column("Check", width=36)
    table.add_column("Status", width=8)
    table.add_column("Detail")

    status_style = {"PASS": "green", "FAIL": "red bold", "WARN": "yellow", "SKIP": "dim"}
    for f in result.findings:
        table.add_row(
            f.control_id,
            f.title,
            f"[{status_style.get(f.status, '')}]{f.status}[/]",
            f.detail,
        )
    console.print(table)
    console.print(
        f"\n[bold]Summary:[/] {result.passed} PASS  "
        f"[red]{result.failed} FAIL[/]  "
        f"(total {len(result.findings)})\n"
    )


def write_markdown(result: AuditResult, path: str = "docs/findings-report.md") -> None:
    lines = [
        "# CIS AWS Findings Report",
        f"\n_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_\n",
        f"**Pass:** {result.passed}  **Fail:** {result.failed}  "
        f"**Total:** {len(result.findings)}\n",
        "| Control | Check | Status | Detail | Remediation |",
        "|---------|-------|--------|--------|-------------|",
    ]
    for f in result.findings:
        lines.append(
            f"| {f.control_id} | {f.title} | {f.status} | {f.detail} | {f.remediation} |"
        )
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    console.print(f"[dim]Report written to {path}[/]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="CIS AWS Foundations audit")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", default="docs/findings-report.md")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    console.print(f"[bold]Auditing account:[/] {account_id}  region: {args.region}\n")

    iam = session.client("iam")
    cloudtrail = session.client("cloudtrail")
    s3_control = session.client("s3control")
    guardduty = session.client("guardduty")

    result = AuditResult()
    result.add(check_root_mfa(iam))
    result.add(check_no_root_access_keys(iam))
    result.add(check_password_policy(iam))
    result.add(check_cloudtrail_enabled(cloudtrail))
    result.add(check_cloudtrail_log_validation(cloudtrail))
    result.add(check_s3_public_access(s3_control, account_id))
    result.add(check_guardduty(guardduty, args.region))

    print_table(result)
    write_markdown(result, args.output)

    sys.exit(1 if result.failed > 0 else 0)


if __name__ == "__main__":
    main()
