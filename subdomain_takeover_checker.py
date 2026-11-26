#!/usr/bin/env python3
"""Subdomain Takeover Checker: find dangling DNS records before an attacker does.

A dependency-free Python CLI. It takes a list of subdomains and their
CNAME targets (a CSV export from your DNS provider, a file, stdin, or
``--cname`` flags), matches each CNAME against a built-in fingerprint
database of cloud services that allow subdomain takeover, and grades
the domain's exposure A-F. With ``--probe`` it also fetches each
subdomain over HTTPS and confirms the takeover by matching the
service's known "not claimed" error page, so a finding is either
"confirmed" or "potential", never a guess.

Usage:
    python3 subdomain_takeover_checker.py examples/sample-dns.csv
    python3 subdomain_takeover_checker.py dns.csv --probe
    cat dns.csv | python3 subdomain_takeover_checker.py -
    python3 subdomain_takeover_checker.py --cname blog=sajid.github.io --cname docs=app.herokuapp.com
    python3 subdomain_takeover_checker.py dns.csv --json --fail-on high
    python3 subdomain_takeover_checker.py --list-services

Exit codes: 0 = pass, 1 = findings at or above --fail-on, 2 = usage/parse error.

Only run this against domains you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__version__ = "1.0.0"
DEFAULT_TIMEOUT = 10

SEVERITY_DEDUCTION = {"high": 25, "medium": 10, "low": 3, "info": 0}
SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Service:
    """One takeover-prone service and how to recognise it.

    ``cname_suffix`` is matched against the end of a CNAME target.
    ``error_strings`` are the distinctive texts the service shows when
    a subdomain points at it but nobody has claimed it. These
    fingerprints are the well-known public ones collected by subdomain
    takeover research (for example the can-i-take-over-xyz list); a
    service can change its error page, so ``--probe`` reports the
    response it actually saw.
    """

    name: str
    cname_suffix: str
    error_strings: tuple[str, ...]
    notes: str = ""
    contains: str = ""  # if set, match when the target contains this (for
    # suffixes that sit mid-hostname, e.g. ".s3-website-eu-west-1.")


SERVICES: tuple[Service, ...] = (
    Service(
        "GitHub Pages",
        ".github.io",
        ("There isn't a GitHub Pages site here.",),
        "Claim the subdomain by adding it to a GitHub Pages site, or remove the CNAME.",
    ),
    Service(
        "AWS S3",
        ".s3.amazonaws.com",
        ("NoSuchBucket", "The specified bucket does not exist"),
        "Delete the bucket's DNS record, or recreate the bucket with the same name.",
    ),
    Service(
        "AWS S3 (website endpoint)",
        ".s3-website",
        ("NoSuchBucket", "The specified bucket does not exist"),
        "Delete the bucket's DNS record, or recreate the bucket with the same name.",
        contains=".s3-website-",
    ),
    Service(
        "Heroku",
        ".herokuapp.com",
        ("No such app",),
        "Claim the subdomain in a Heroku app, or remove the CNAME.",
    ),
    Service(
        "Microsoft Azure",
        ".azurewebsites.net",
        ("404 Web Site not found",),
        "Claim the subdomain in an Azure App Service, or remove the CNAME.",
    ),
    Service(
        "Microsoft Azure (Traffic Manager)",
        ".trafficmanager.net",
        ("404 Web Site not found",),
        "Claim the subdomain in an Azure App Service, or remove the CNAME.",
    ),
    Service(
        "Shopify",
        ".myshopify.com",
        ("Sorry, this shop is currently unavailable.",),
        "Claim the subdomain in a Shopify store, or remove the CNAME.",
    ),
    Service(
        "Tumblr",
        ".tumblr.com",
        ("There's nothing here.",),
        "Claim the subdomain in a Tumblr blog, or remove the CNAME.",
    ),
    Service(
        "WordPress.com",
        ".wordpress.com",
        ("Do you want to register",),
        "Claim the subdomain in a WordPress.com site, or remove the CNAME.",
    ),
    Service(
        "Squarespace",
        ".squarespace.com",
        ("No Such Account",),
        "Claim the subdomain in a Squarespace site, or remove the CNAME.",
    ),
    Service(
        "Netlify",
        ".netlify.app",
        ("Not Found - Request ID:",),
        "Claim the subdomain in a Netlify site, or remove the CNAME.",
    ),
    Service(
        "Vercel",
        ".vercel.app",
        ("404: NOT_FOUND",),
        "Claim the subdomain in a Vercel project, or remove the CNAME.",
    ),
    Service(
        "AWS CloudFront",
        ".cloudfront.net",
        ("ERROR: The request could not be satisfied",),
        "Claim the subdomain in a CloudFront distribution, or remove the CNAME.",
    ),
    Service(
        "Fastly",
        ".fastly.net",
        ("Fastly error: unknown domain",),
        "Claim the subdomain in a Fastly service, or remove the CNAME.",
    ),
    Service(
        "Pantheon",
        ".pantheonsite.io",
        ("The gods are wise, but do not know the site you seek.",),
        "Claim the subdomain in a Pantheon site, or remove the CNAME.",
    ),
    Service(
        "Zendesk",
        ".zendesk.com",
        ("Help Center Closed",),
        "Claim the subdomain in a Zendesk help centre, or remove the CNAME.",
    ),
    Service(
        "Bitbucket",
        ".bitbucket.io",
        ("Repository not found",),
        "Claim the subdomain in a Bitbucket Cloud workspace, or remove the CNAME.",
    ),
    Service(
        "GitLab Pages",
        ".gitlab.io",
        ("The page you're looking for could not be found.",),
        "Claim the subdomain in a GitLab Pages project, or remove the CNAME.",
    ),
    Service(
        "Surge.sh",
        ".surge.sh",
        ("project not found",),
        "Claim the subdomain in a Surge project, or remove the CNAME.",
    ),
)


def service_for_cname(cname: str) -> Service | None:
    """Return the takeover-prone service a CNAME points at, or None."""
    target = cname.strip().lower().rstrip(".")
    for service in SERVICES:
        if service.contains and service.contains in target:
            return service
        if target.endswith(service.cname_suffix):
            return service
    return None


@dataclass
class Record:
    """One subdomain and its CNAME target (empty target = no CNAME)."""

    subdomain: str
    cname: str = ""


@dataclass
class Finding:
    """One problem found, with the fix in plain language."""

    severity: str  # "high" | "medium" | "low" | "info"
    source: str
    message: str
    fix: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "fix": self.fix,
        }


@dataclass
class CheckedRecord:
    """The result of checking one DNS record."""

    subdomain: str
    cname: str
    service: str | None = None
    status: str = "clean"  # clean | potential | confirmed | unknown | no_cname | probe_error
    probe_detail: str | None = None

    def as_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "service": self.service,
            "status": self.status,
            "probe_detail": self.probe_detail,
        }


@dataclass
class Report:
    """The full result of one DNS list analysis."""

    source: str | None
    records: int = 0
    checked: int = 0
    potential: int = 0
    confirmed: int = 0
    unknown_services: int = 0
    no_cname: int = 0
    probe_errors: int = 0
    score: int = 100
    grade: str = "A"
    findings: list[Finding] = field(default_factory=list)
    results: list[CheckedRecord] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "counts": {
                "records": self.records,
                "checked": self.checked,
                "potential": self.potential,
                "confirmed": self.confirmed,
                "unknown_services": self.unknown_services,
                "no_cname": self.no_cname,
                "probe_errors": self.probe_errors,
            },
            "score": self.score,
            "grade": self.grade,
            "findings": [f.as_dict() for f in self.findings],
            "results": [r.as_dict() for r in self.results],
        }


def grade_for(score: int) -> str:
    """Convert a 0-100 score to an A-F grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def parse_records(text: str) -> tuple[list[Record], int]:
    """Parse DNS records from text.

    Accepted formats, one record per line:
      - CSV: ``subdomain,cname`` (a header row ``subdomain,cname`` is skipped)
      - Space or tab separated: ``subdomain cname``
      - A subdomain alone (no CNAME) counts as a record with no CNAME.
    Blank lines and lines starting with ``#`` are ignored. Returns
    (records, malformed_lines): a line with more than two fields, or a
    ``--cname``-style ``subdomain=target`` pair split wrongly, is
    counted malformed and skipped.
    """
    records: list[Record] = []
    malformed = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields: list[str] = []
        if "," in line:
            try:
                fields = next(csv.reader(io.StringIO(line)))
            except csv.Error:
                malformed += 1
                continue
        else:
            fields = line.split()
        fields = [f.strip() for f in fields]
        if len(fields) == 1:
            subdomain, cname = fields[0], ""
        elif len(fields) == 2:
            subdomain, cname = fields
        else:
            malformed += 1
            continue
        if subdomain.lower() in ("subdomain", "host", "name") and cname.lower() in (
            "cname",
            "target",
            "value",
            "",
        ):
            continue  # header row
        if not subdomain:
            malformed += 1
            continue
        records.append(Record(subdomain=subdomain, cname=cname))
    return records, malformed


def parse_cname_flag(value: str) -> Record:
    """Parse one ``--cname subdomain=target`` value into a Record."""
    if "=" not in value:
        raise ValueError(f"--cname value must be subdomain=target, got {value!r}")
    subdomain, cname = value.split("=", 1)
    subdomain = subdomain.strip()
    cname = cname.strip()
    if not subdomain:
        raise ValueError(f"--cname value must be subdomain=target, got {value!r}")
    return Record(subdomain=subdomain, cname=cname)


def probe_subdomain(subdomain: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[str | None, str | None]:
    """Fetch https://subdomain and return (body, error).

    Returns (body, None) on a successful fetch, even for HTTP error
    statuses, because a 404 page is exactly what a takeover check
    needs to read. Returns (None, error) only when the request itself
    fails (DNS, connection, timeout, TLS). The caller decides what the
    body means.
    """
    url = f"https://{subdomain}/"
    request = urllib.request.Request(url, headers={"User-Agent": "subdomain-takeover-checker/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
        return body, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - a broken error body is not fatal
            body = ""
        return body, None
    except Exception as exc:  # noqa: BLE001 - DNS, TLS and timeouts are expected here
        return None, f"{type(exc).__name__}: {exc}"


def check_records(
    records: list[Record],
    source: str | None = None,
    probe: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> Report:
    """Check a list of DNS records for subdomain takeover exposure.

    This is a pure function of its inputs apart from the optional live
    probe, so it is easy to test offline with synthetic records.
    ``probe`` is False by default: without it, a CNAME that matches a
    takeover-prone service is reported as "potential" (medium). With
    ``--probe``, a matching error page confirms it (high); a live,
    claimed site clears it; a failed probe keeps it potential and
    records the error.
    """
    findings: list[Finding] = []
    results: list[CheckedRecord] = []
    potential = confirmed = unknown_services = no_cname = probe_errors = 0

    for record in records:
        cname = record.cname.strip()
        if not cname:
            no_cname += 1
            results.append(
                CheckedRecord(
                    subdomain=record.subdomain,
                    cname="",
                    status="no_cname",
                )
            )
            continue
        service = service_for_cname(cname)
        if service is None:
            unknown_services += 1
            results.append(
                CheckedRecord(
                    subdomain=record.subdomain,
                    cname=cname,
                    status="unknown",
                )
            )
            continue
        if not probe:
            potential += 1
            results.append(
                CheckedRecord(
                    subdomain=record.subdomain,
                    cname=cname,
                    service=service.name,
                    status="potential",
                )
            )
            findings.append(
                Finding(
                    "medium",
                    record.subdomain,
                    f"Potential subdomain takeover: {record.subdomain} points "
                    f"at {service.name} ({cname}) and the service was not "
                    "probed, so it is not known whether the subdomain is "
                    "claimed. A CNAME to a takeover-prone service that "
                    "nobody owns can be claimed by an attacker.",
                    f"Run with --probe to confirm, or check the {service.name} "
                    f"account for {record.subdomain}. {service.notes}",
                )
            )
            continue
        body, error = probe_subdomain(record.subdomain, timeout=timeout)
        if error is not None:
            probe_errors += 1
            potential += 1
            results.append(
                CheckedRecord(
                    subdomain=record.subdomain,
                    cname=cname,
                    service=service.name,
                    status="probe_error",
                    probe_detail=error,
                )
            )
            findings.append(
                Finding(
                    "medium",
                    record.subdomain,
                    f"Potential subdomain takeover: {record.subdomain} points "
                    f"at {service.name} ({cname}) and the probe failed "
                    f"({error}), so it could not be confirmed or cleared. "
                    "A CNAME to a takeover-prone service that nobody owns "
                    "can be claimed by an attacker.",
                    f"Check the {service.name} account for "
                    f"{record.subdomain} by hand, and re-run with --probe "
                    f"once the subdomain resolves. {service.notes}",
                )
            )
            continue
        matched = [text for text in service.error_strings if text in (body or "")]
        if matched:
            confirmed += 1
            results.append(
                CheckedRecord(
                    subdomain=record.subdomain,
                    cname=cname,
                    service=service.name,
                    status="confirmed",
                    probe_detail=f"matched error text: {matched[0]!r}",
                )
            )
            findings.append(
                Finding(
                    "high",
                    record.subdomain,
                    f"Confirmed subdomain takeover: {record.subdomain} "
                    f"points at {service.name} ({cname}) and the live "
                    f"site shows the service's unclaimed error "
                    f"({matched[0]!r}). Anyone can claim this subdomain "
                    "on the service right now.",
                    f"Claim {record.subdomain} in the {service.name} "
                    f"account immediately, or delete the CNAME record. "
                    f"{service.notes}",
                )
            )
        else:
            results.append(
                CheckedRecord(
                    subdomain=record.subdomain,
                    cname=cname,
                    service=service.name,
                    status="clean",
                    probe_detail="live site does not show the unclaimed error page",
                )
            )

    if not findings and records:
        findings.append(
            Finding(
                "info",
                "dns",
                "No subdomain takeover exposure found: no CNAME points "
                "at a takeover-prone service, or every probed subdomain "
                "is claimed and serving a live site.",
                "Keep checking: DNS records change whenever a service is "
                "cancelled. Re-run this tool after any migration or "
                "decommission.",
            )
        )

    score = 100
    for finding in findings:
        score -= SEVERITY_DEDUCTION[finding.severity]
    score = max(0, score)

    return Report(
        source=source,
        records=len(records),
        checked=len(records),
        potential=potential,
        confirmed=confirmed,
        unknown_services=unknown_services,
        no_cname=no_cname,
        probe_errors=probe_errors,
        score=score,
        grade=grade_for(score),
        findings=findings,
        results=results,
    )


def format_report(report: Report, malformed: int = 0) -> str:
    """Render a report as plain text."""
    lines: list[str] = []
    title = report.source or "DNS records"
    lines.append(f"Subdomain takeover report: {title}")
    lines.append(f"Score: {report.score}/100  Grade: {report.grade}")
    lines.append("")
    lines.append("Summary:")
    lines.append(f"  Records checked: {report.records}")
    if malformed:
        lines.append(f"  Malformed lines skipped: {malformed}")
    lines.append(f"  Confirmed takeovers: {report.confirmed}")
    lines.append(f"  Potential takeovers: {report.potential}")
    lines.append(f"  CNAMEs to other services: {report.unknown_services}")
    lines.append(f"  Records with no CNAME: {report.no_cname}")
    if report.probe_errors:
        lines.append(f"  Probes that failed: {report.probe_errors}")
    if report.results:
        lines.append("")
        lines.append("Records:")
        for result in report.results:
            status = result.status.replace("_", " ")
            detail = f" -> {result.service}" if result.service else ""
            lines.append(f"  {result.subdomain:<28} {status}{detail}")
            if result.probe_detail:
                lines.append(f"      {result.probe_detail}")
    if report.findings:
        lines.append("")
        lines.append(f"Findings ({len(report.findings)}):")
        for finding in report.findings:
            lines.append(
                f"  [{finding.severity.upper()}] {finding.source}: "
                f"{finding.message}"
            )
            lines.append(f"        Fix: {finding.fix}")
    else:
        lines.append("")
        lines.append("No findings: no CNAME points at a takeover-prone service.")
    return "\n".join(lines)


def format_services() -> str:
    """Render the fingerprint database as plain text."""
    lines = [
        f"Takeover-prone services ({len(SERVICES)} fingerprints):",
        "",
    ]
    for service in SERVICES:
        lines.append(f"  {service.name}")
        lines.append(f"    CNAME suffix: *{service.cname_suffix}")
        for text in service.error_strings:
            lines.append(f"    Unclaimed error text: {text!r}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="subdomain_takeover_checker.py",
        description=(
            "Check a list of subdomains and their CNAME targets for "
            "subdomain takeover exposure, and grade the domain A-F. "
            "Only run this against domains you own or are authorised "
            "to test."
        ),
    )
    parser.add_argument(
        "dnsfile",
        nargs="?",
        help="CSV file of subdomain,cname records, e.g. dns.csv. Use '-' to read from stdin.",
    )
    parser.add_argument(
        "--cname",
        action="append",
        default=[],
        metavar="SUBDOMAIN=TARGET",
        help="One record given on the command line, e.g. --cname blog=sajid.github.io. Repeatable.",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Fetch each subdomain over HTTPS and confirm a takeover by matching the service's unclaimed error page. Without this, matches are reported as potential.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Seconds to wait for each probe response. Default: {DEFAULT_TIMEOUT}.",
    )
    parser.add_argument("--json", action="store_true", help="Print the report as JSON instead of plain text.")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "none"],
        default="none",
        help="Exit 1 when findings at or above this severity are found. Default: none.",
    )
    parser.add_argument(
        "--list-services",
        action="store_true",
        help="List the takeover-prone services this tool recognises, then exit.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if args.list_services:
        print(format_services())
        return 0

    try:
        if args.timeout < 1:
            parser.error("--timeout must be at least 1")
        records: list[Record] = []
        malformed = 0
        source: str | None = None
        if args.dnsfile is not None:
            if args.dnsfile == "-":
                text = sys.stdin.read()
                source = "stdin"
            else:
                try:
                    with open(args.dnsfile, encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                except OSError as exc:
                    raise ValueError(f"could not read {args.dnsfile} ({exc})") from exc
                source = args.dnsfile
            records, malformed = parse_records(text)
        for value in args.cname:
            try:
                records.append(parse_cname_flag(value))
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        if args.dnsfile is None and not args.cname:
            parser.error("Give a DNS file to check, or records with --cname")
        if not records and malformed == 0:
            parser.error("No DNS records found to check")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    report = check_records(records, source=source, probe=args.probe, timeout=args.timeout)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(format_report(report, malformed=malformed))

    if args.fail_on != "none":
        threshold_order = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold_order for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
