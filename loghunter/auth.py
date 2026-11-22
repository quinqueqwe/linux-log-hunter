"""Анализ /var/log/auth.log (sshd): подбор пароля, перебор имён, вход после подбора.

Оптимизации относительно naive-версии:
  * файл читается потоком, в памяти только короткие окна по «активным» IP;
  * строки без "sshd[" отбрасываются простой проверкой подстроки (до регулярки);
  * время переводится в секунды без datetime: эпоха минуты кэшируется (<= 10 тыс. записей в неделю логов);
  * окна считаются очередью (deque): добавили справа, убрали устаревшее слева, O(1) на событие;
  * один всплеск = один алерт, а не по алерту на каждое событие.
"""
import calendar
import re
from collections import deque

from .config import DEFAULT

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
_ACCEPT = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port")
_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")

_PRUNE_EVERY = 1 << 18  # раз в ~260 тыс. строк чистим устаревшие окна, чтобы память не росла


def analyze_auth(path, year, cfg=DEFAULT):
    bf_n, bf_w = cfg.bf_n, cfg.bf_window
    en_n, en_w = cfg.enum_n, cfg.enum_window
    comp_w = cfg.compromise_window

    fail_win = {}      # ip -> deque времён неудачных входов
    active = {}        # ip -> алерт «идёт подбор»
    bf_last = {}       # ip -> время последнего подбора (для проверки успешного входа)
    enum_win = {}      # ip -> deque (время, имя)
    enum_active = {}   # ip -> алерт «идёт перебор имён»
    alerts = []
    minute_base = {}   # "Nov  1 00:00" -> эпоха начала минуты
    mget = minute_base.get
    fail_search, accept_search, invalid_search = _FAIL.search, _ACCEPT.search, _INVALID.search

    def to_ts(line):
        key = line[:12]
        base = mget(key)
        if base is None:
            base = minute_base[key] = calendar.timegm(
                (year, _MONTHS[key[:3]], int(key[4:6]), int(key[7:9]), int(key[10:12]), 0))
        return base + int(line[13:15])

    def prune(now):
        for ip in [ip for ip, dq in fail_win.items() if not dq or dq[-1] <= now - bf_w]:
            del fail_win[ip]
            active.pop(ip, None)
        for ip in [ip for ip, dq in enum_win.items() if not dq or dq[-1][0] <= now - en_w]:
            del enum_win[ip]
            enum_active.pop(ip, None)
        for ip in [ip for ip, t in bf_last.items() if now - t > comp_w]:
            del bf_last[ip]

    n = 0
    ts = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            n += 1
            if not n & (_PRUNE_EVERY - 1):
                prune(ts)
            if "sshd[" not in line:
                continue

            if "Failed password for " in line:
                m = fail_search(line, 15)
                if m is None:
                    continue
                ip = m.group(2)
                ts = to_ts(line)
                dq = fail_win.get(ip)
                if dq is None:
                    dq = fail_win[ip] = deque()
                dq.append(ts)
                cutoff = ts - bf_w
                while dq[0] <= cutoff:
                    dq.popleft()
                size = len(dq)
                if size >= bf_n:
                    a = active.get(ip)
                    if a is None:
                        a = active[ip] = {"type": "ssh_bruteforce", "key": ip,
                                          "first_seen": dq[0], "count": 0, "user": m.group(1)}
                        alerts.append(a)
                    if size > a["count"]:
                        a["count"] = size
                    a["last_seen"] = ts
                    bf_last[ip] = ts
                elif ip in active:
                    del active[ip]

            elif "Accepted " in line:
                m = accept_search(line, 15)
                if m is None:
                    continue
                ip = m.group(2)
                last = bf_last.get(ip)
                if last is not None:
                    ts = to_ts(line)
                    if 0 <= ts - last <= comp_w:
                        alerts.append({"type": "ssh_compromise", "key": ip, "first_seen": ts,
                                       "count": 1, "user": m.group(1)})
                        del bf_last[ip]

            elif "Invalid user " in line:
                m = invalid_search(line, 15)
                if m is None:
                    continue
                ip = m.group(2)
                ts = to_ts(line)
                dq = enum_win.get(ip)
                if dq is None:
                    dq = enum_win[ip] = deque()
                dq.append((ts, m.group(1)))
                cutoff = ts - en_w
                while dq[0][0] <= cutoff:
                    dq.popleft()
                distinct = len({u for _, u in dq})
                if distinct >= en_n:
                    a = enum_active.get(ip)
                    if a is None:
                        a = enum_active[ip] = {"type": "ssh_user_enum", "key": ip,
                                               "first_seen": dq[0][0], "count": 0}
                        alerts.append(a)
                    if distinct > a["count"]:
                        a["count"] = distinct
                elif ip in enum_active:
                    del enum_active[ip]

    return alerts
