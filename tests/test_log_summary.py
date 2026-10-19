import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
import log_summary

SAMPLE = BASE / "tests" / "sample_auth.log"


class LogSummaryTests(unittest.TestCase):
    def setUp(self):
        self.lines = SAMPLE.read_text().splitlines()
        self.summary = log_summary.summarize(self.lines)

    def test_failed_login_count(self):
        self.assertEqual(self.summary["failed_logins"], 4)

    def test_accepted_count(self):
        self.assertEqual(self.summary["accepted_logins"], 1)

    def test_failed_by_user(self):
        users = dict(self.summary["failed_by_user"])
        self.assertEqual(users["admin"], 2)
        self.assertEqual(users["root"], 2)

    def test_top_ip(self):
        self.assertEqual(self.summary["failed_by_ip"][0][0], "203.0.113.9")

    def test_invalid_users(self):
        names = dict(self.summary["invalid_user_names"])
        self.assertEqual(names["test"], 1)
        self.assertEqual(self.summary["invalid_users"], 1)

    def test_sudo_commands(self):
        commands = dict(self.summary["sudo_commands"])
        self.assertIn("/usr/bin/pacman -Syu", commands)

    def test_render(self):
        text = log_summary.render(self.summary, top=2)
        self.assertIn("failed logins:   4", text)

    def test_cli_json(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = log_summary.main([str(SAMPLE), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["failed_logins"], 4)

    def test_missing_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(log_summary.main(["/nope/auth.log"]), 2)


if __name__ == "__main__":
    unittest.main()
