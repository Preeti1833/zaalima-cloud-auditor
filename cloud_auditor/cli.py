"""Cloud Infrastructure Auditor & Cost Optimizer — CLI entry point."""

from __future__ import annotations

from typing import List, Optional

import typer
from rich.console import Console

from cloud_auditor import __version__
from cloud_auditor.auth import AuthError, get_aws_session, get_gcp_context
from cloud_auditor.cleanup import execute_cleanup, load_findings_from_report, print_dry_run
from cloud_auditor.report import export as export_report
from cloud_auditor.report import render_findings_table
from cloud_auditor.scanners import Finding
from cloud_auditor.scanners.aws_ebs import scan_unattached_ebs_volumes
from cloud_auditor.scanners.aws_ec2 import scan_underutilized_ec2_instances
from cloud_auditor.scanners.aws_eip import scan_unassociated_eips
from cloud_auditor.scanners.gcp_scanner import (
    scan_idle_gcp_addresses,
    scan_underutilized_gcp_instances,
    scan_unattached_gcp_disks,
)
from cloud_auditor.utils import parse_region_list

app = typer.Typer(
    name="cloud-auditor",
    help="Audit AWS/GCP infrastructure for waste and generate cost-saving reports.",
    add_completion=True,
)
scan_app = typer.Typer(help="Run scans against a cloud provider.")
app.add_typer(scan_app, name="scan")

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"cloud-auditor {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    )
) -> None:
    """Cloud Infrastructure Auditor & Cost Optimizer."""


@scan_app.command("aws")
def scan_aws(
    profile: Optional[str] = typer.Option(None, help="Local AWS named profile to use."),
    assume_role_arn: Optional[str] = typer.Option(
        None, "--assume-role-arn", help="IAM role ARN to assume before scanning."
    ),
    regions: Optional[str] = typer.Option(
        None, help="Comma-separated regions to scan. Defaults to all enabled regions."
    ),
    lookback_days: int = typer.Option(14, help="Days of CloudWatch history for EC2 CPU checks."),
    cpu_threshold: float = typer.Option(5.0, help="CPU%% below which an instance is flagged."),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export path (.json or .csv). Table always prints to screen."
    ),
    skip_ebs: bool = typer.Option(False, help="Skip the unattached-EBS-volume scan."),
    skip_eip: bool = typer.Option(False, help="Skip the unassociated-Elastic-IP scan."),
    skip_ec2: bool = typer.Option(False, help="Skip the underutilized-EC2 scan."),
) -> None:
    """Scan an AWS account for orphaned/underutilized/misconfigured resources."""
    try:
        ctx = get_aws_session(profile=profile, assume_role_arn=assume_role_arn)
    except AuthError as exc:
        console.print(f"[bold red]Auth error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    target_regions = parse_region_list(regions, ctx.session)
    console.print(
        f"Scanning AWS account [bold]{ctx.account_id}[/bold] across "
        f"{len(target_regions)} region(s): {', '.join(target_regions)}\n"
    )

    findings: List[Finding] = []
    with console.status("[bold cyan]Scanning...", spinner="dots"):
        for region in target_regions:
            if not skip_ebs:
                findings.extend(scan_unattached_ebs_volumes(ctx.session, region, ctx.account_id))
            if not skip_eip:
                findings.extend(scan_unassociated_eips(ctx.session, region, ctx.account_id))
            if not skip_ec2:
                findings.extend(
                    scan_underutilized_ec2_instances(
                        ctx.session,
                        region,
                        ctx.account_id,
                        lookback_days=lookback_days,
                        cpu_threshold_pct=cpu_threshold,
                    )
                )

    render_findings_table(findings, title=f"AWS Audit — Account {ctx.account_id}")

    if output:
        path = export_report(findings, output)
        console.print(f"\nReport exported to [bold]{path}[/bold]")


@scan_app.command("gcp")
def scan_gcp(
    project: Optional[str] = typer.Option(None, help="GCP project ID. Inferred from ADC if omitted."),
    lookback_days: int = typer.Option(14, help="Days of Cloud Monitoring history for CPU checks."),
    cpu_threshold: float = typer.Option(5.0, help="CPU%% below which an instance is flagged."),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export path (.json or .csv). Table always prints to screen."
    ),
    skip_disks: bool = typer.Option(False, help="Skip the unattached-disk scan."),
    skip_addresses: bool = typer.Option(False, help="Skip the idle-static-IP scan."),
    skip_instances: bool = typer.Option(False, help="Skip the underutilized-instance scan."),
) -> None:
    """Scan a GCP project for orphaned/underutilized/misconfigured resources."""
    try:
        gcp_ctx = get_gcp_context(project=project)
    except AuthError as exc:
        console.print(f"[bold red]Auth error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"Scanning GCP project [bold]{gcp_ctx.project}[/bold]\n")

    findings: List[Finding] = []
    with console.status("[bold cyan]Scanning...", spinner="dots"):
        if not skip_disks:
            findings.extend(scan_unattached_gcp_disks(gcp_ctx.credentials, gcp_ctx.project))
        if not skip_addresses:
            findings.extend(scan_idle_gcp_addresses(gcp_ctx.credentials, gcp_ctx.project))
        if not skip_instances:
            findings.extend(
                scan_underutilized_gcp_instances(
                    gcp_ctx.credentials,
                    gcp_ctx.project,
                    lookback_days=lookback_days,
                    cpu_threshold_pct=cpu_threshold,
                )
            )

    render_findings_table(findings, title=f"GCP Audit — Project {gcp_ctx.project}")

    if output:
        path = export_report(findings, output)
        console.print(f"\nReport exported to [bold]{path}[/bold]")


@app.command("cleanup")
def cleanup(
    report: str = typer.Argument(..., help="Path to a previously exported .json report."),
    execute: bool = typer.Option(
        False, "--execute", help="Actually perform the cleanup (default is dry-run)."
    ),
) -> None:
    """Preview (default) or execute cleanup actions from a saved report.

    Execution always requires typing the confirmation phrase interactively —
    there is no flag to skip this, by design.
    """
    findings = load_findings_from_report(report)

    if not execute:
        print_dry_run(findings)
        console.print(
            "\n[dim]This was a dry run. Re-run with --execute to actually perform cleanup.[/dim]"
        )
        return

    print_dry_run(findings)
    console.print(
        f"\n[bold red]You are about to run {len(findings)} destructive command(s) "
        f"against live cloud resources.[/bold red]"
    )
    typed = typer.prompt("Type DELETE (all caps) to confirm, or anything else to cancel")
    if typed != "DELETE":
        console.print("[yellow]Cancelled. No changes were made.[/yellow]")
        raise typer.Exit(code=0)

    execute_cleanup(findings, confirm_token=typed)


if __name__ == "__main__":
    app()
