"""Command-line interface for the local-lab foundation."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from netprobe import __version__
from netprobe.assessment import run_assessment
from netprobe.checks.http import run_checks
from netprobe.dns import query_dns, validate_dns_request
from netprobe.enumeration.service import inspect_service
from netprobe.models import AssessmentMetadata
from netprobe.reporting.render import render_report, write_report
from netprobe.scanner.tcp import PORT_PROFILES, get_ports, scan_tcp, validate_scan_request
from netprobe.scope import ScopeError, load_scope
from netprobe.storage.artifacts import (
    ArtifactError,
    latest_artifact,
    load_json_artifact,
    write_json_artifact,
)

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_UNAVAILABLE = 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Loopback-only assessment utilities for isolated labs.",
        epilog=(
            "Examples: netprobe validate-scope --scope scope.yaml; "
            "netprobe assess --scope scope.yaml --dry-run; "
            "netprobe scan --scope scope.yaml --target 127.0.0.1 --ports 22,80 "
            "--i-have-authorization"
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-scope", help="validate an authorized scope file")
    validate.add_argument("--scope", required=True, type=Path)
    assess = commands.add_parser("assess", help="validate scope and preview assessment metadata")
    assess.add_argument("--scope", required=True, type=Path)
    assess.add_argument("--dry-run", action="store_true", help="perform no network activity")
    assess.add_argument("--target", help="one loopback host explicitly present in the scope")
    assess_selection = assess.add_mutually_exclusive_group()
    assess_selection.add_argument("--ports", help="comma-separated ports/ranges (up to 64)")
    assess_selection.add_argument("--profile", choices=tuple(PORT_PROFILES), default="common")
    assess.add_argument("--concurrency", type=int, default=8)
    assess.add_argument("--timeout", type=float, default=1.0, help="maximum 5 seconds")
    assess.add_argument(
        "--i-have-authorization", action="store_true", help="confirm authorization for this lab"
    )
    assess.add_argument("--artifact-dir", type=Path, default=Path("netprobe-data/assessments"))
    scan = commands.add_parser("scan", help="check selected TCP ports on a loopback lab host")
    scan.add_argument("--scope", required=True, type=Path)
    scan.add_argument("--target", required=True, help="localhost or a literal loopback IP")
    selection = scan.add_mutually_exclusive_group()
    selection.add_argument("--ports", help="comma-separated ports/ranges (up to 64 unique ports)")
    selection.add_argument("--profile", choices=tuple(PORT_PROFILES))
    scan.add_argument("--concurrency", type=int, default=8)
    scan.add_argument("--timeout", type=float, default=0.75, help="per-port timeout, maximum 5s")
    scan.add_argument("--dry-run", action="store_true", help="validate and preview without sockets")
    scan.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm authorization for this active local-lab check",
    )
    enumerate_cmd = commands.add_parser(
        "enumerate", help="collect one bounded, non-authenticating loopback service observation"
    )
    enumerate_cmd.add_argument("--scope", required=True, type=Path)
    enumerate_cmd.add_argument("--target", required=True, help="localhost or a literal loopback IP")
    enumerate_cmd.add_argument("--port", required=True, type=int)
    enumerate_cmd.add_argument(
        "--protocol",
        choices=("auto", "tcp", "http", "https", "ssh", "smtp", "ftp"),
        default="auto",
    )
    enumerate_cmd.add_argument("--timeout", type=float, default=2.0, help="maximum 5 seconds")
    enumerate_cmd.add_argument("--dry-run", action="store_true", help="validate without sockets")
    enumerate_cmd.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm authorization for this active local-lab observation",
    )
    check_http = commands.add_parser(
        "check-http", help="inspect one scoped loopback HTTP response and run safe header checks"
    )
    check_http.add_argument("--scope", required=True, type=Path)
    check_http.add_argument("--target", required=True, help="localhost or a literal loopback IP")
    check_http.add_argument("--port", type=int, default=80)
    check_http.add_argument("--timeout", type=float, default=2.0, help="maximum 5 seconds")
    check_http.add_argument("--dry-run", action="store_true", help="validate without sockets")
    check_http.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm authorization for this active local-lab check",
    )
    check_http.add_argument(
        "--artifact-dir",
        type=Path,
        default=Path("netprobe-data/assessments"),
        help="directory for private assessment JSON records",
    )
    dns_check = commands.add_parser(
        "dns-check",
        help="query one reserved lab DNS name through an explicitly scoped loopback server",
    )
    dns_check.add_argument("--scope", required=True, type=Path)
    dns_check.add_argument("--server", required=True, help="explicit loopback DNS server IP")
    dns_check.add_argument("--name", required=True, help="localhost or a reserved .test name")
    dns_check.add_argument("--type", choices=("A", "AAAA", "MX", "NS", "TXT"), default="A")
    dns_check.add_argument("--timeout", type=float, default=2.0, help="maximum 3 seconds")
    dns_check.add_argument("--dry-run", action="store_true", help="validate without DNS traffic")
    dns_check.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm authorization for this local lab",
    )
    report = commands.add_parser("report", help="render a stored assessment as JSON, CSV, or HTML")
    report.add_argument("--assessment", required=True, help="artifact path or 'latest'")
    report.add_argument("--artifact-dir", type=Path, default=Path("netprobe-data/assessments"))
    report.add_argument("--format", required=True, choices=("json", "csv", "html"))
    report.add_argument("--output-dir", type=Path, default=Path("netprobe-data/reports"))
    report.add_argument("--name", help="safe report filename stem (defaults to assessment ID)")
    report.add_argument(
        "--overwrite", action="store_true", help="explicitly replace existing report"
    )
    commands.add_parser("version", help="show installed version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "version":
        print(f"NetProbe {__version__}")
        return EXIT_OK
    if args.command == "report":
        try:
            artifact_path = (
                latest_artifact(args.artifact_dir)
                if args.assessment == "latest"
                else Path(args.assessment)
            )
            artifact = load_json_artifact(artifact_path)
            report_text = render_report(artifact, args.format)
            report_name = args.name or str(artifact["metadata"].get("assessment_id", "assessment"))
            output_path = write_report(
                args.output_dir,
                report_name,
                args.format,
                report_text,
                overwrite=args.overwrite,
            )
        except (ArtifactError, ValueError) as exc:
            print(f"report error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        print(json.dumps({"report": str(output_path), "format": args.format}, indent=2))
        return EXIT_OK
    try:
        scope = load_scope(args.scope)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    if args.command == "validate-scope":
        print(
            json.dumps(
                {
                    "valid": True,
                    "authorized_targets": [target.original for target in scope.authorized_targets],
                    "exclusions": [target.original for target in scope.exclusions],
                    "authorization_confirmed": scope.authorization_confirmed,
                    "boundary": "loopback-only",
                },
                indent=2,
            )
        )
        return EXIT_OK

    if args.command == "dns-check":
        try:
            normalized_name = validate_dns_request(scope, args.server, args.name, args.type)
            if not 0 < args.timeout <= 3:
                raise ValueError("DNS timeout must be greater than 0 and at most 3 seconds")
        except (ScopeError, ValueError) as exc:
            print(f"DNS check input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "dry_run": True,
                        "network_activity": False,
                        "server": args.server,
                        "name": normalized_name,
                        "type": args.type,
                    },
                    indent=2,
                )
            )
            return EXIT_OK
        if not args.i_have_authorization:
            print("active DNS check requires --i-have-authorization", file=sys.stderr)
            return EXIT_INPUT_ERROR
        dns_result = asyncio.run(
            query_dns(
                scope,
                args.server,
                args.name,
                args.type,
                timeout=args.timeout,
            )
        )
        print(json.dumps(dns_result.as_dict(), indent=2))
        return EXIT_OK

    if args.command == "enumerate":
        try:
            validate_scan_request(
                scope,
                args.target,
                (args.port,),
                concurrency=1,
                timeout=args.timeout,
            )
        except (ScopeError, ValueError) as exc:
            print(f"enumeration input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "dry_run": True,
                        "network_activity": False,
                        "target": args.target,
                        "port": args.port,
                        "protocol": args.protocol,
                    },
                    indent=2,
                )
            )
            return EXIT_OK
        if not args.i_have_authorization:
            print("active enumeration requires --i-have-authorization", file=sys.stderr)
            return EXIT_INPUT_ERROR
        try:
            observation = asyncio.run(
                inspect_service(
                    scope,
                    args.target,
                    args.port,
                    protocol=args.protocol,
                    timeout=args.timeout,
                )
            )
        except (ScopeError, ValueError) as exc:
            print(f"enumeration input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        print(json.dumps(observation.as_dict(), indent=2))
        return EXIT_OK

    if args.command == "check-http":
        try:
            validate_scan_request(
                scope, args.target, (args.port,), concurrency=1, timeout=args.timeout
            )
        except (ScopeError, ValueError) as exc:
            print(f"HTTP check input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "dry_run": True,
                        "network_activity": False,
                        "target": args.target,
                        "port": args.port,
                        "checks": ["HTTP-SECURITY-HEADERS-001", "HTTP-COOKIE-ATTRIBUTES-001"],
                    },
                    indent=2,
                )
            )
            return EXIT_OK
        if not args.i_have_authorization:
            print("active HTTP checks require --i-have-authorization", file=sys.stderr)
            return EXIT_INPUT_ERROR
        observation = asyncio.run(
            inspect_service(
                scope,
                args.target,
                args.port,
                protocol="http",
                timeout=args.timeout,
            )
        )
        findings = run_checks(observation)
        metadata = AssessmentMetadata(
            tool_version=__version__,
            scope_file=str(args.scope),
            authorized_targets=[target.original for target in scope.authorized_targets],
            exclusions=[target.original for target in scope.exclusions],
            authorization_confirmed=scope.authorization_confirmed,
            profile="check-http",
            limitations=[
                "Loopback-only single-response HTTP HEAD check.",
                "Security-header observations require manual validation.",
                "Cookie values are not recorded; only attribute presence is retained.",
            ],
            completed_at=datetime.now(UTC),
        )
        artifact = {
            "schema_version": 1,
            "metadata": metadata.model_dump(mode="json"),
            "observations": [observation.as_dict()],
            "findings": [
                finding.model_dump(mode="json") | {"priority_score": finding.priority_score}
                for finding in findings
            ],
        }
        try:
            artifact_path = write_json_artifact(args.artifact_dir, metadata.assessment_id, artifact)
        except ArtifactError as exc:
            print(f"artifact error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        print(
            json.dumps(
                {
                    "observation": observation.as_dict(),
                    "findings": [
                        finding.model_dump(mode="json") | {"priority_score": finding.priority_score}
                        for finding in findings
                    ],
                    "assessment_artifact": str(artifact_path),
                },
                indent=2,
            )
        )
        return EXIT_OK

    if args.command == "scan":
        try:
            selected_profile = args.profile or ("common" if args.ports is None else None)
            selected_ports = get_ports(profile=selected_profile, ports=args.ports)
            validate_scan_request(
                scope,
                args.target,
                selected_ports,
                concurrency=args.concurrency,
                timeout=args.timeout,
            )
        except (ScopeError, ValueError) as exc:
            print(f"scan input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "dry_run": True,
                        "network_activity": False,
                        "target": args.target,
                        "ports": list(selected_ports),
                        "profile": selected_profile,
                    },
                    indent=2,
                )
            )
            return EXIT_OK
        if not args.i_have_authorization:
            print("active scan requires --i-have-authorization", file=sys.stderr)
            return EXIT_INPUT_ERROR
        try:
            results = asyncio.run(
                scan_tcp(
                    scope,
                    args.target,
                    selected_ports,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                )
            )
        except (ScopeError, ValueError) as exc:
            print(f"scan input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        print(
            json.dumps(
                {"target": args.target, "results": [item.as_dict() for item in results]},
                indent=2,
            )
        )
        return EXIT_OK

    if args.command == "assess":
        try:
            selected_profile = args.profile if args.ports is None else None
            selected_ports = get_ports(profile=selected_profile, ports=args.ports)
            if args.target is not None:
                validate_scan_request(
                    scope,
                    args.target,
                    selected_ports,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                )
            elif not args.dry_run:
                raise ValueError("active assess requires --target with one loopback host")
            elif not 1 <= args.concurrency <= 16 or not 0 < args.timeout <= 5:
                raise ValueError("concurrency or timeout is outside supported limits")
        except (ScopeError, ValueError) as exc:
            print(f"assessment input error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "dry_run": True,
                        "network_activity": False,
                        "target": args.target,
                        "ports": list(selected_ports),
                        "profile": selected_profile,
                        "authorized_targets": [
                            target.original for target in scope.authorized_targets
                        ],
                    },
                    indent=2,
                )
            )
            return EXIT_OK
        if not args.i_have_authorization:
            print("active assessment requires --i-have-authorization", file=sys.stderr)
            return EXIT_INPUT_ERROR
        if args.target is None:
            print("active assess requires --target", file=sys.stderr)
            return EXIT_INPUT_ERROR
        started_at = datetime.now(UTC)
        try:
            assessment_result = asyncio.run(
                run_assessment(
                    scope,
                    args.target,
                    selected_ports,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                )
            )
        except (ScopeError, ValueError) as exc:
            print(f"assessment error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        metadata = AssessmentMetadata(
            tool_version=__version__,
            scope_file=str(args.scope),
            authorized_targets=[target.original for target in scope.authorized_targets],
            exclusions=[target.original for target in scope.exclusions],
            authorization_confirmed=scope.authorization_confirmed,
            profile=selected_profile or "explicit-ports",
            started_at=started_at,
            completed_at=datetime.now(UTC),
            limitations=assessment_result.limitations,
        )
        observations = [
            {
                "host": item.host,
                "port": item.port,
                "protocol": "tcp",
                "status": item.state.value,
                "details": {"detail": item.detail, "checked_at": item.checked_at},
            }
            for item in assessment_result.port_results
        ] + [item.as_dict() for item in assessment_result.observations]
        artifact = {
            "schema_version": 1,
            "metadata": metadata.model_dump(mode="json"),
            "observations": observations,
            "findings": [
                finding.model_dump(mode="json") | {"priority_score": finding.priority_score}
                for finding in assessment_result.findings
            ],
        }
        try:
            artifact_path = write_json_artifact(args.artifact_dir, metadata.assessment_id, artifact)
        except ArtifactError as exc:
            print(f"artifact error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        print(
            json.dumps(
                {
                    "assessment_id": metadata.assessment_id,
                    "target": args.target,
                    "port_count": len(assessment_result.port_results),
                    "open_ports": [
                        result_port.port
                        for result_port in assessment_result.port_results
                        if result_port.state.value == "open"
                    ],
                    "finding_count": len(assessment_result.findings),
                    "artifact": str(artifact_path),
                },
                indent=2,
            )
        )
        return EXIT_OK
    targets = [target.original for target in scope.authorized_targets]
    print(
        json.dumps(
            {
                "dry_run": True,
                "network_activity": False,
                "profile": args.profile,
                "authorized_targets": targets,
                "exclusions": [target.original for target in scope.exclusions],
                "authorization_confirmed": scope.authorization_confirmed,
                "note": "No hosts were contacted; this command only previews validated scope.",
            },
            indent=2,
        )
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
