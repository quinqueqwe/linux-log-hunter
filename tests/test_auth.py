import os
import tempfile
import unittest

from loghunter.auth import analyze_auth


def fail(sec, ip="203.0.113.9", user="root"):
    return f"Nov  1 10:00:{sec:02d} srv sshd[1]: Failed password for {user} from {ip} port 4000 ssh2"


def accepted(sec, ip="203.0.113.9"):
    return f"Nov  1 10:01:{sec:02d} srv sshd[1]: Accepted password for root from {ip} port 4000 ssh2"


def invalid(sec, user, ip="203.0.113.7"):
    return f"Nov  1 10:00:{sec:02d} srv sshd[1]: Invalid user {user} from {ip} port 4000"


def run(lines):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "auth.log")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        return analyze_auth(p, 2026)


def types(alerts):
    return sorted((a["type"], a["key"]) for a in alerts)


class BruteForceTests(unittest.TestCase):
    def test_below_threshold_no_alert(self):
        self.assertEqual(run([fail(i) for i in range(4)]), [])

    def test_threshold_gives_one_alert(self):
        alerts = run([fail(i) for i in range(5)])
        self.assertEqual(types(alerts), [("ssh_bruteforce", "203.0.113.9")])

    def test_long_burst_is_still_one_alert(self):
        alerts = run([fail(i) for i in range(30)])
        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(alerts[0]["count"], 5)

    def test_slow_attempts_outside_window_no_alert(self):
        # 5 неудач, но по одной раз в 20 секунд: в любом окне 60 с их максимум 3
        lines = [f"Nov  1 10:{(i * 20) // 60:02d}:{(i * 20) % 60:02d} srv sshd[1]: "
                 f"Failed password for root from 203.0.113.9 port 4000 ssh2" for i in range(5)]
        self.assertEqual(run(lines), [])

    def test_different_ips_do_not_add_up(self):
        lines = [fail(i, ip=f"203.0.113.{i}") for i in range(10)]
        self.assertEqual(run(lines), [])

    def test_new_burst_after_pause_is_new_alert(self):
        first = [fail(i) for i in range(5)]
        second = [f"Nov  1 11:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2"
                  for i in range(5)]
        self.assertEqual(len(run(first + second)), 2)

    def test_non_sshd_lines_ignored(self):
        self.assertEqual(run(["Nov  1 10:00:00 srv CRON[1]: (root) CMD (x)"] * 10), [])


class CompromiseTests(unittest.TestCase):
    def test_login_after_bruteforce_is_critical_event(self):
        alerts = run([fail(i) for i in range(6)] + [accepted(30)])
        self.assertIn(("ssh_compromise", "203.0.113.9"), types(alerts))

    def test_login_without_bruteforce_is_fine(self):
        self.assertEqual(run([accepted(5)]), [])

    def test_login_long_after_bruteforce_not_flagged(self):
        late = "Nov  1 12:00:00 srv sshd[1]: Accepted password for root from 203.0.113.9 port 1 ssh2"
        alerts = run([fail(i) for i in range(6)] + [late])
        self.assertNotIn("ssh_compromise", [a["type"] for a in alerts])


class UserEnumTests(unittest.TestCase):
    def test_many_distinct_users_alerts(self):
        names = ["a", "b", "c", "d", "e"]
        alerts = run([invalid(i, n) for i, n in enumerate(names)])
        self.assertEqual(types(alerts), [("ssh_user_enum", "203.0.113.7")])

    def test_same_user_repeated_is_not_enumeration(self):
        self.assertEqual(run([invalid(i, "admin") for i in range(10)]), [])


if __name__ == "__main__":
    unittest.main()
