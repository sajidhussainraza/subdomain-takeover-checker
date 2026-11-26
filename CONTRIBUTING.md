# Contributing to Subdomain Takeover Checker

Thanks for helping make Subdomain Takeover Checker better. This is
a small, dependency-free tool, and contributions that keep it that way
are especially welcome.

## Quick steps

1. Fork the repository and clone your fork.
2. Create a branch for your change:
   `git checkout -b fix/describe-the-change`
3. Make the change. Keep the tool Python standard library only; do not
   add third-party dependencies.
4. Add or update tests in `tests/` for any behaviour you change.
5. Run the full suite and make sure all tests pass:
   `python3 tests/run_tests.py`
6. Run a smoke check of the CLI:
   `python3 subdomain_takeover_checker.py examples/sample-dns.csv`
7. Open a pull request describing the change and why it helps. Fill in
   the pull request template.

## What to work on

- A new service fingerprint, with a real CNAME suffix and the
  service's real unclaimed error text, a test, and a README entry in
  the "What it checks" table. Do not add a fingerprint you have not
  verified: a wrong error string turns a live site into a false
  confirmed takeover.
- A corrected error string for a service that changed its unclaimed
  page, with evidence (the response you saw).
- Better plain-language wording for a finding or its fix.
- Documentation fixes, typo corrections, and clearer examples.
- Bug reports: include the command you ran, the DNS records involved
  (use example domains, never a real domain you do not own), and the
  output you got versus what you expected.

## Ground rules

- Only test domains you own or are authorised to test. This tool is
  for finding your own dangling records, not for scanning other
  people's domains.
- Never include a real vulnerable domain in an issue or a pull
  request. Use `example.com` subdomains in examples, as the sample
  file does.
- Keep the tool dependency-free (Python standard library only).
