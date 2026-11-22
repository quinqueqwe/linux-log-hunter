"""Анализ nginx access.log (формат combined): сканирование, атаки по сигнатурам, всплеск 5xx."""
import calendar
import re
from collections import deque

from .config import DEFAULT, WEB_SIGNATURES

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

_SIG = re.compile("|".join(re.escape(s) for s in WEB_SIGNATURES), re.IGNORECASE)

_PRUNE_EVERY = 1 << 18


def analyze_nginx(path, cfg=DEFAULT):
    scan_n, scan_w, spike_n = cfg.scan_n, cfg.scan_window, cfg.spike_n

    scan_win = {}      # ip -> deque времён ответов 4xx
    scan_active = {}   # ip -> алерт
    sig_alerts = {}    # ip -> алерт «атака по сигнатуре»
    spikes = {}        # начало минуты -> число ответов 5xx
    alerts = []
    minute_base = {}   # "01/Nov/2026:00:00" -> эпоха начала минуты
    mget = minute_base.get
    sig_search = _SIG.search
    find = str.find

    def prune(now):
        for ip in [ip for ip, dq in scan_win.items() if not dq or dq[-1] <= now - scan_w]:
            del scan_win[ip]
            scan_active.pop(ip, None)

    n = 0
    ts = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            n += 1
            if not n & (_PRUNE_EVERY - 1):
                prune(ts)
            sp = find(line, " ")
            lb = find(line, "[", sp)
            q1 = find(line, '"', lb)
            q2 = find(line, '"', q1 + 1)
            if sp < 0 or lb < 0 or q1 < 0 or q2 < 0:
                continue
            status = line[q2 + 2:q2 + 5]
            if not status.isdigit():
                continue

            key = line[lb + 1:lb + 18]
            base = mget(key)
            if base is None:
                base = minute_base[key] = calendar.timegm(
                    (int(key[7:11]), _MONTHS[key[3:6]], int(key[:2]), int(key[12:14]), int(key[15:17]), 0))
            ts = base + int(line[lb + 19:lb + 21])
            ip = line[:sp]

            # сигнатуры атак в пути запроса
            first = find(line, " ", q1)
            if first != -1:
                end = find(line, " ", first + 1, q2)
                path_part = line[first + 1:end if end != -1 else q2]
                if sig_search(path_part):
                    a = sig_alerts.get(ip)
                    if a is None:
                        a = sig_alerts[ip] = {"type": "web_attack", "key": ip, "first_seen": ts,
                                              "count": 0, "path": path_part[:120]}
                        alerts.append(a)
                    a["count"] += 1

            c = status[0]
            if c == "4":
                dq = scan_win.get(ip)
                if dq is None:
                    dq = scan_win[ip] = deque()
                dq.append(ts)
                cutoff = ts - scan_w
                while dq[0] <= cutoff:
                    dq.popleft()
                size = len(dq)
                if size >= scan_n:
                    a = scan_active.get(ip)
                    if a is None:
                        a = scan_active[ip] = {"type": "web_scan", "key": ip, "first_seen": dq[0], "count": 0}
                        alerts.append(a)
                    if size > a["count"]:
                        a["count"] = size
                elif ip in scan_active:
                    del scan_active[ip]
            elif c == "5":
                minute = ts - ts % 60
                count = spikes.get(minute, 0) + 1
                spikes[minute] = count
                if count == spike_n:
                    alerts.append({"type": "availability_spike", "key": minute,
                                   "first_seen": minute, "count": count})
                elif count > spike_n:
                    for a in reversed(alerts):  # обновляем счётчик последнего всплеска этой минуты
                        if a["type"] == "availability_spike" and a["key"] == minute:
                            a["count"] = count
                            break

    return alerts
