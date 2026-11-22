"""Проверка, что быстрая версия находит ровно то же, что простая, и совпадает с эталоном генератора."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from loghunter.auth import analyze_auth
from loghunter.web import analyze_nginx
from naive.naive_analyzer import analyze as naive_analyze

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class EquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_logs.py"),
                        "--lines", "30000", "--out", cls.tmp.name, "--seed", "7"],
                       check=True, capture_output=True)
        cls.auth = os.path.join(cls.tmp.name, "auth.log")
        cls.nginx = os.path.join(cls.tmp.name, "access.log")
        with open(os.path.join(cls.tmp.name, "truth.json")) as f:
            cls.truth = {tuple(x) for x in json.load(f)["alerts"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_fast_matches_ground_truth(self):
        alerts = analyze_auth(self.auth, 2026) + analyze_nginx(self.nginx)
        self.assertEqual({(a["type"], a["key"]) for a in alerts}, self.truth)

    def test_fast_matches_naive(self):
        fast = analyze_auth(self.auth, 2026) + analyze_nginx(self.nginx)
        slow = naive_analyze(self.auth, self.nginx, 2026)
        self.assertEqual({(a["type"], a["key"]) for a in fast}, {(a["type"], a["key"]) for a in slow})


if __name__ == "__main__":
    unittest.main()
