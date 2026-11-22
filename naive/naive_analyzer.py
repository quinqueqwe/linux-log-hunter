"""v1: первая, «в лоб» написанная версия. Нужна как точка отсчёта для замеров.

Что в ней сделано просто и медленно (и что исправлено в loghunter):
  * весь файл читается в память (readlines);
  * каждая строка проходит через re.search с неразобранной строкой-шаблоном;
  * время разбирается через datetime.strptime на каждой строке;
  * каждое событие хранится как словарь;
  * окна считаются перебором событий одного IP.
"""
import calendar
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

from loghunter.config import DEFAULT, WEB_SIGNATURES


def parse_auth(path, year):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    events = []
    for line in lines:
        m = re.search(r"^(\w{3}\s+\d+ \d\d:\d\d:\d\d) \S+ sshd\[\d+\]: (.*)$", line)
        if not m:
            continue
        msg = m.group(2)
        kind = None
        m2 = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+) port", msg)
        if m2:
            kind = "fail"
        else:
            m2 = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+) port", msg)
            if m2:
                kind = "accepted"
            else:
                m2 = re.search(r"Invalid user (\S+) from (\S+)", msg)
                if m2:
                    kind = "invalid"
        if kind is None:
            continue
        when = datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        events.append({"time": calendar.timegm(when.timetuple()), "kind": kind,
                       "user": m2.group(1), "ip": m2.group(2)})
    return events


def parse_nginx(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    events = []
    for line in lines:
        m = re.search(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) ', line)
        if not m:
            continue
        when = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z")
        events.append({"time": calendar.timegm(when.utctimetuple()), "ip": m.group(1),
                       "path": m.group(4), "status": int(m.group(5))})
    return events


def window_hits(times, size, need):
    """Времена (отсортированные), в конце которых за `size` секунд набралось `need` событий."""
    hits = []
    for t in times:
        inside = [x for x in times if t - size < x <= t]
        if len(inside) >= need:
            hits.append(t)
    return hits


def analyze_auth(path, year, cfg=DEFAULT):
    events = parse_auth(path, year)
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    alerts = []
    for ip, evs in by_ip.items():
        fails = sorted(e["time"] for e in evs if e["kind"] == "fail")
        hits = window_hits(fails, cfg.bf_window, cfg.bf_n)
        if hits:
            alerts.append({"type": "ssh_bruteforce", "key": ip, "first_seen": hits[0]})
            for acc in (e["time"] for e in evs if e["kind"] == "accepted"):
                if any(0 <= acc - h <= cfg.compromise_window for h in hits):
                    alerts.append({"type": "ssh_compromise", "key": ip, "first_seen": acc})
                    break

        invalid = sorted((e["time"], e["user"]) for e in evs if e["kind"] == "invalid")
        for t, _ in invalid:
            users = {u for x, u in invalid if t - cfg.enum_window < x <= t}
            if len(users) >= cfg.enum_n:
                alerts.append({"type": "ssh_user_enum", "key": ip, "first_seen": t})
                break
    return alerts


def analyze_nginx(path, cfg=DEFAULT):
    events = parse_nginx(path)
    alerts = []

    by_ip = defaultdict(list)
    for e in events:
        if 400 <= e["status"] < 500:
            by_ip[e["ip"]].append(e["time"])
    for ip, times in by_ip.items():
        times.sort()
        hits = window_hits(times, cfg.scan_window, cfg.scan_n)
        if hits:
            alerts.append({"type": "web_scan", "key": ip, "first_seen": hits[0]})

    seen = set()
    for e in events:
        low = e["path"].lower()
        if e["ip"] not in seen and any(sig in low for sig in WEB_SIGNATURES):
            seen.add(e["ip"])
            alerts.append({"type": "web_attack", "key": e["ip"], "first_seen": e["time"]})

    per_minute = Counter(e["time"] // 60 * 60 for e in events if e["status"] >= 500)
    for minute, count in sorted(per_minute.items()):
        if count >= cfg.spike_n:
            alerts.append({"type": "availability_spike", "key": minute, "first_seen": minute})
    return alerts


def analyze(auth_path, nginx_path, year, cfg=DEFAULT):
    return analyze_auth(auth_path, year, cfg) + analyze_nginx(nginx_path, cfg)


if __name__ == "__main__":
    for a in analyze(sys.argv[1], sys.argv[2], int(sys.argv[3])):
        print(a)
