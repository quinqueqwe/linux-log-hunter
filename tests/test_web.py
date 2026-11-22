import os
import tempfile
import unittest

from loghunter.web import analyze_nginx


def req(sec, ip="203.0.113.5", path="/x", status=404, minute=0):
    return (f'{ip} - - [01/Nov/2026:10:{minute:02d}:{sec:02d} +0000] "GET {path} HTTP/1.1" {status} 10 "-" "curl/8"')


def run(lines):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "access.log")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        return analyze_nginx(p)


def types(alerts):
    return sorted((a["type"], a["key"]) for a in alerts)


class ScanTests(unittest.TestCase):
    def test_19_errors_no_alert(self):
        self.assertEqual(run([req(i) for i in range(19)]), [])

    def test_20_errors_in_a_minute_is_scan(self):
        self.assertEqual(types(run([req(i) for i in range(20)])), [("web_scan", "203.0.113.5")])

    def test_successful_requests_are_not_scan(self):
        self.assertEqual(run([req(i % 60, status=200) for i in range(100)]), [])


class SignatureTests(unittest.TestCase):
    def test_path_traversal(self):
        alerts = run([req(1, path="/download?file=../../etc/passwd", status=200)])
        self.assertEqual(types(alerts), [("web_attack", "203.0.113.5")])

    def test_sql_injection_case_insensitive(self):
        alerts = run([req(1, path="/a.php?id=1%20UNION%20SELECT%201", status=200)])
        self.assertEqual(len(alerts), 1)

    def test_normal_paths_not_flagged(self):
        self.assertEqual(run([req(1, path="/blog/post-1", status=200)]), [])

    def test_repeated_hits_are_one_alert_with_counter(self):
        alerts = run([req(i, path="/.env", status=404) for i in range(3)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 3)


class SpikeTests(unittest.TestCase):
    def test_100_errors_in_a_minute_is_spike(self):
        lines = [req(i % 60, ip=f"198.18.0.{i % 200 + 1}", path="/api", status=502) for i in range(100)]
        alerts = run(lines)
        self.assertEqual([a["type"] for a in alerts], ["availability_spike"])

    def test_99_errors_no_spike(self):
        lines = [req(i % 60, ip=f"198.18.0.{i + 1}", path="/api", status=502) for i in range(99)]
        self.assertEqual(run(lines), [])

    def test_errors_spread_over_minutes_no_spike(self):
        lines = [req(i % 60, ip=f"198.18.0.{i % 200 + 1}", path="/api", status=500, minute=i % 10)
                 for i in range(100)]
        self.assertEqual(run(lines), [])


class RobustnessTests(unittest.TestCase):
    def test_garbage_lines_do_not_crash(self):
        self.assertEqual(run(["", "garbage", '1.2.3.4 - - [bad] "x" abc', "\x00\x01"]), [])


if __name__ == "__main__":
    unittest.main()
