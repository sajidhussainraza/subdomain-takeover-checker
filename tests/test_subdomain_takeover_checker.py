"""Tests for subdomain_takeover_checker (stdlib unittest, all offline).

Probe tests run against a local HTTP server started in a thread; no
real network is used. The local server cannot serve HTTPS, so probe
tests patch ``probe_subdomain`` instead of calling the network, and
one test exercises the real ``probe_subdomain`` against a local plain
HTTP server through a monkeypatched ``urllib.request.urlopen`` that
rewrites the scheme.
"""

import io
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subdomain_takeover_checker as stc


def make_records(*pairs):
    return [stc.Record(sub, cname) for sub, cname in pairs]


class ServiceFingerprintTests(unittest.TestCase):
    def test_github_pages_suffix(self):
        self.assertEqual(stc.service_for_cname("sajid.github.io").name, "GitHub Pages")

    def test_github_pages_trailing_dot(self):
        self.assertEqual(stc.service_for_cname("sajid.github.io.").name, "GitHub Pages")

    def test_case_insensitive(self):
        self.assertEqual(stc.service_for_cname("APP.HEROKUAPP.COM").name, "Heroku")

    def test_s3_website_endpoint(self):
        service = stc.service_for_cname("bucket.s3-website-eu-west-1.amazonaws.com")
        self.assertEqual(service.name, "AWS S3 (website endpoint)")

    def test_azure_traffic_manager(self):
        service = stc.service_for_cname("app.trafficmanager.net")
        self.assertEqual(service.name, "Microsoft Azure (Traffic Manager)")

    def test_unknown_service_returns_none(self):
        self.assertIsNone(stc.service_for_cname("api.example.net"))

    def test_substring_is_not_a_match(self):
        # "notgithub.io" does not end with ".github.io"
        self.assertIsNone(stc.service_for_cname("notgithub.io"))

    def test_every_service_has_error_strings(self):
        for service in stc.SERVICES:
            self.assertTrue(service.error_strings, service.name)
            self.assertTrue(service.cname_suffix.startswith("."), service.name)

    def test_no_duplicate_suffixes(self):
        suffixes = [s.cname_suffix for s in stc.SERVICES]
        self.assertEqual(len(suffixes), len(set(suffixes)))


class ParseRecordsTests(unittest.TestCase):
    def test_csv_with_header(self):
        records, malformed = stc.parse_records("subdomain,cname\nblog.example.com,sajid.github.io\n")
        self.assertEqual(records, [stc.Record("blog.example.com", "sajid.github.io")])
        self.assertEqual(malformed, 0)

    def test_space_separated(self):
        records, malformed = stc.parse_records("blog.example.com sajid.github.io\n")
        self.assertEqual(records, [stc.Record("blog.example.com", "sajid.github.io")])
        self.assertEqual(malformed, 0)

    def test_subdomain_alone(self):
        records, _ = stc.parse_records("www.example.com\n")
        self.assertEqual(records, [stc.Record("www.example.com", "")])

    def test_comments_and_blank_lines_ignored(self):
        records, malformed = stc.parse_records("# comment\n\nblog.example.com,sajid.github.io\n")
        self.assertEqual(len(records), 1)
        self.assertEqual(malformed, 0)

    def test_three_fields_is_malformed(self):
        _, malformed = stc.parse_records("a.example.com,b.github.io,extra\n")
        self.assertEqual(malformed, 1)

    def test_empty_input(self):
        records, malformed = stc.parse_records("")
        self.assertEqual(records, [])
        self.assertEqual(malformed, 0)


class ParseCnameFlagTests(unittest.TestCase):
    def test_valid_flag(self):
        self.assertEqual(
            stc.parse_cname_flag("blog=sajid.github.io"),
            stc.Record("blog", "sajid.github.io"),
        )

    def test_missing_equals_raises(self):
        with self.assertRaises(ValueError):
            stc.parse_cname_flag("blog")

    def test_empty_subdomain_raises(self):
        with self.assertRaises(ValueError):
            stc.parse_cname_flag("=sajid.github.io")


class CheckRecordsTests(unittest.TestCase):
    def test_empty_records_gives_clean_score(self):
        report = stc.check_records([])
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.findings, [])

    def test_no_cname_is_clean(self):
        report = stc.check_records(make_records(("www.example.com", "")))
        self.assertEqual(report.no_cname, 1)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.findings[0].severity, "info")

    def test_unknown_service_is_clean(self):
        report = stc.check_records(make_records(("api.example.com", "api.example.net")))
        self.assertEqual(report.unknown_services, 1)
        self.assertEqual(report.score, 100)

    def test_potential_is_medium(self):
        report = stc.check_records(make_records(("blog.example.com", "sajid.github.io")))
        self.assertEqual(report.potential, 1)
        self.assertEqual(report.score, 90)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.findings[0].severity, "medium")
        self.assertIn("Potential", report.findings[0].message)
        self.assertEqual(report.results[0].status, "potential")
        self.assertEqual(report.results[0].service, "GitHub Pages")

    def test_sample_file_scores_20(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "examples", "sample-dns.csv")
        with open(path, encoding="utf-8") as handle:
            records, malformed = stc.parse_records(handle.read())
        self.assertEqual(malformed, 0)
        report = stc.check_records(records)
        self.assertEqual(report.records, 10)
        self.assertEqual(report.potential, 8)
        self.assertEqual(report.no_cname, 1)
        self.assertEqual(report.unknown_services, 1)
        self.assertEqual(report.score, 20)
        self.assertEqual(report.grade, "F")

    def test_grading_boundaries(self):
        self.assertEqual(stc.grade_for(100), "A")
        self.assertEqual(stc.grade_for(90), "A")
        self.assertEqual(stc.grade_for(89), "B")
        self.assertEqual(stc.grade_for(80), "B")
        self.assertEqual(stc.grade_for(79), "C")
        self.assertEqual(stc.grade_for(70), "C")
        self.assertEqual(stc.grade_for(69), "D")
        self.assertEqual(stc.grade_for(60), "D")
        self.assertEqual(stc.grade_for(59), "F")
        self.assertEqual(stc.grade_for(0), "F")


class ProbeTests(unittest.TestCase):
    def test_confirmed_takeover_when_error_page_matches(self):
        with mock.patch.object(
            stc, "probe_subdomain", return_value=("There isn't a GitHub Pages site here.", None)
        ):
            report = stc.check_records(
                make_records(("blog.example.com", "sajid.github.io")), probe=True
            )
        self.assertEqual(report.confirmed, 1)
        self.assertEqual(report.score, 75)
        self.assertEqual(report.grade, "C")
        self.assertEqual(report.findings[0].severity, "high")
        self.assertIn("Confirmed", report.findings[0].message)
        self.assertEqual(report.results[0].status, "confirmed")

    def test_claimed_site_is_clean(self):
        with mock.patch.object(
            stc, "probe_subdomain", return_value=("<html>My real site</html>", None)
        ):
            report = stc.check_records(
                make_records(("blog.example.com", "sajid.github.io")), probe=True
            )
        self.assertEqual(report.confirmed, 0)
        self.assertEqual(report.potential, 0)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.results[0].status, "clean")

    def test_probe_failure_stays_potential(self):
        with mock.patch.object(
            stc, "probe_subdomain", return_value=(None, "URLError: Name or service not known")
        ):
            report = stc.check_records(
                make_records(("blog.example.com", "sajid.github.io")), probe=True
            )
        self.assertEqual(report.probe_errors, 1)
        self.assertEqual(report.potential, 1)
        self.assertEqual(report.score, 90)
        self.assertEqual(report.results[0].status, "probe_error")

    def test_heroku_error_string_confirms(self):
        with mock.patch.object(
            stc, "probe_subdomain", return_value=("No such app", None)
        ):
            report = stc.check_records(
                make_records(("docs.example.com", "app.herokuapp.com")), probe=True
            )
        self.assertEqual(report.confirmed, 1)

    def test_s3_error_string_confirms(self):
        with mock.patch.object(
            stc, "probe_subdomain", return_value=("<?xml?><Error><Code>NoSuchBucket</Code></Error>", None)
        ):
            report = stc.check_records(
                make_records(("files.example.com", "bucket.s3.amazonaws.com")), probe=True
            )
        self.assertEqual(report.confirmed, 1)


class LiveProbeTests(unittest.TestCase):
    """Exercise the real probe_subdomain against a local HTTP server."""

    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"There isn't a GitHub Pages site here."
                self.send_response(404)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_real_probe_reads_error_page(self):
        # probe_subdomain builds an https URL; rewrite the scheme so it
        # hits the local plain-HTTP server instead.
        real_urlopen = stc.urllib.request.urlopen

        def fake_urlopen(request, timeout=None):
            url = request.full_url.replace("https://", "http://", 1)
            url = url.replace("blog.example.com", f"127.0.0.1:{self.port}", 1)
            return real_urlopen(url, timeout=timeout)

        with mock.patch.object(stc.urllib.request, "urlopen", side_effect=fake_urlopen):
            body, error = stc.probe_subdomain("blog.example.com", timeout=5)
        self.assertIsNone(error)
        self.assertIn("There isn't a GitHub Pages site here.", body)


class ReportOutputTests(unittest.TestCase):
    def test_json_shape(self):
        report = stc.check_records(make_records(("blog.example.com", "sajid.github.io")))
        data = report.as_dict()
        self.assertEqual(data["score"], 90)
        self.assertEqual(data["grade"], "A")
        self.assertEqual(data["counts"]["potential"], 1)
        self.assertEqual(data["findings"][0]["severity"], "medium")
        self.assertEqual(data["results"][0]["status"], "potential")
        json.dumps(data)  # must be JSON-serialisable

    def test_text_report_contains_score_and_finding(self):
        report = stc.check_records(make_records(("blog.example.com", "sajid.github.io")))
        text = stc.format_report(report)
        self.assertIn("Score: 90/100  Grade: A", text)
        self.assertIn("[MEDIUM] blog.example.com", text)
        self.assertIn("GitHub Pages", text)

    def test_clean_text_report(self):
        report = stc.check_records(make_records(("www.example.com", "")))
        text = stc.format_report(report)
        self.assertIn("Score: 100/100  Grade: A", text)
        self.assertIn("No subdomain takeover exposure found", text)

    def test_list_services_output(self):
        text = stc.format_services()
        self.assertIn("GitHub Pages", text)
        self.assertIn(".github.io", text)
        self.assertIn("Heroku", text)
        self.assertIn("AWS S3", text)


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        with mock.patch.object(sys, "argv", ["subdomain_takeover_checker.py"] + argv):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                    try:
                        code = stc.main()
                    except SystemExit as exc:
                        code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_version_flag(self):
        code, out, _ = self.run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("1.0.0", out)

    def test_list_services_flag(self):
        code, out, _ = self.run_cli(["--list-services"])
        self.assertEqual(code, 0)
        self.assertIn("GitHub Pages", out)

    def test_cname_flag(self):
        code, out, _ = self.run_cli(["--cname", "blog=sajid.github.io"])
        self.assertEqual(code, 0)
        self.assertIn("Score: 90/100", out)

    def test_fail_on_medium_exits_1(self):
        code, _, _ = self.run_cli(["--cname", "blog=sajid.github.io", "--fail-on", "medium"])
        self.assertEqual(code, 1)

    def test_fail_on_high_exits_0_for_potential(self):
        code, _, _ = self.run_cli(["--cname", "blog=sajid.github.io", "--fail-on", "high"])
        self.assertEqual(code, 0)

    def test_no_input_exits_2(self):
        code, _, err = self.run_cli([])
        self.assertEqual(code, 2)

    def test_bad_cname_flag_exits_2(self):
        code, _, _ = self.run_cli(["--cname", "blog"])
        self.assertEqual(code, 2)

    def test_missing_file_exits_2(self):
        code, _, _ = self.run_cli(["/nonexistent/dns.csv"])
        self.assertEqual(code, 2)

    def test_json_flag(self):
        code, out, _ = self.run_cli(["--cname", "blog=sajid.github.io", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["counts"]["potential"], 1)

    def test_sample_file_via_cli(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "examples", "sample-dns.csv")
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("Score: 20/100  Grade: F", out)
        self.assertIn("Findings (8)", out)

    def test_help_flag(self):
        code, out, _ = self.run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("subdomain takeover", out.lower())


if __name__ == "__main__":
    unittest.main()
