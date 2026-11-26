# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-24

### Added

- Dependency-free Python CLI that checks a list of subdomains and
  their CNAME targets for subdomain takeover exposure and grades the
  domain's exposure A-F with a 0-100 score.
- A built-in fingerprint database of 19 takeover-prone services
  (GitHub Pages, AWS S3, Heroku, Microsoft Azure, Shopify, Tumblr,
  WordPress.com, Squarespace, Netlify, Vercel, AWS CloudFront,
  Fastly, Pantheon, Zendesk, Bitbucket, GitLab Pages, Surge.sh),
  each with its CNAME suffix and the distinctive error text the
  service shows when a subdomain points at it but nobody has
  claimed it.
- A two-level result: without `--probe`, a matching CNAME is a
  "potential" takeover (medium); with `--probe`, the tool fetches
  the subdomain over HTTPS and a matching error page confirms the
  takeover (high), while a live claimed site clears it. A probe
  that fails (DNS, connection, timeout, TLS) keeps the record
  potential and records the error instead of guessing.
- Plain-language findings with a concrete fix for every issue, a
  per-record table showing each subdomain's status and service,
  and a summary of counts.
- A clean-domain note (severity `info`, no deduction) when no CNAME
  points at a takeover-prone service, so a clean domain is reported,
  not hidden.
- Input from a CSV file (`subdomain,cname`, with or without a header
  row), from stdin (`-`), or inline with repeatable `--cname
  subdomain=target` flags; `--list-services` prints the fingerprint
  database; machine-readable output (`--json`); a CI gate
  (`--fail-on {high,medium,low,none}`, default `none`); a
  configurable probe timeout (`--timeout`, default 10); and a
  `--version` flag.
- Exit codes 0 (pass), 1 (findings at or above `--fail-on`),
  2 (usage or file error).
- Malformed lines are skipped and counted, never fatal: a corrupt
  line does not stop the analysis.
- 45 tests (stdlib `unittest`, no pytest needed), including a test
  that the shipped sample DNS export scores 20/100, grade F, and
  probe tests against a local HTTP server (no real network).
- A synthetic sample DNS export (`examples/sample-dns.csv`, 10
  records) with real saved text and JSON output, covering 8
  potential takeovers across 8 services, one record with no CNAME,
  and one CNAME to an unrecognised service.
- Full repository standard: README, CONTRIBUTING.md, Code of Conduct,
  Security policy, issue and pull request templates, CI workflow,
  `.gitignore`, `.editorconfig`, and original SVG banner and logo.

### Fixed

- Nothing yet; this is the first release.

## [Unreleased]

- Nothing yet. See the [roadmap](README.md#roadmap) for what is planned.
