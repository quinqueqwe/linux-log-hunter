#!/usr/bin/env python3
"""Генератор синтетических логов для проверки loghunter.

Создаёт два файла, похожих на настоящие:
  * auth.log   (формат syslog, записи sshd, cron, systemd)
  * access.log (формат nginx combined)

В обычный «фоновый» трафик подмешиваются атаки, о которых мы заранее знаем,
и записывает их в truth.json. По этому эталону tools/benchmark.py считает
точность и полноту обнаружения.

Пример:
    python tools/gen_logs.py --lines 1000000 --out data/1m
"""
import argparse
import calendar
import datetime
import json
import os
import random

BASE = calendar.timegm((2026, 11, 1, 0, 0, 0))  # начало периода, UTC
SPAN = 7 * 24 * 3600  # неделя логов
UTC = datetime.timezone.utc

ATTACK_USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "pi"]
ENUM_USERS = ["guest", "user", "support", "ftpuser", "tomcat", "jenkins", "zabbix", "deploy"]
SCAN_PATHS = ["/admin", "/phpmyadmin/", "/wp-admin/", "/manager/html", "/cgi-bin/test.cgi",
              "/server-status", "/backup.zip", "/config.php", "/solr/admin", "/actuator/health"]
ATTACK_PATHS = [
    "/index.php?id=1'%20UNION%20SELECT%201,2,3--",
    "/download?file=../../../etc/passwd",
    "/.env",
    "/.git/config",
    "/search?q=<script>alert(1)</script>",
    "/cgi-bin/..%2f..%2fwindows/system32/cmd.exe",
]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "curl/8.5.0",
]


def syslog_ts(t):
    d = datetime.datetime.fromtimestamp(t, UTC)
    return f"{d.strftime('%b')} {d.day:2d} {d:%H:%M:%S}"


def nginx_ts(t):
    return datetime.datetime.fromtimestamp(t, UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=100_000, help="строк в КАЖДОМ файле")
    ap.add_argument("--out", default="data/sample", help="папка для результата")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    n = args.lines
    k = max(3, n // 20000)  # сколько атак каждого типа
    os.makedirs(args.out, exist_ok=True)

    used = set()

    def attacker_ip():
        while True:
            ip = f"{rng.choice([45, 91, 103, 141, 185, 193, 218])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            if ip not in used:
                used.add(ip)
                return ip

    def start_time(length):
        return BASE + rng.randint(300, SPAN - length - 600)

    truth = {"lines_per_file": n, "span_days": 7, "alerts": []}
    auth_inj, web_inj = [], []

    def sshd(t, text):
        auth_inj.append((t, f"{syslog_ts(t)} srv-01 sshd[{rng.randint(1000, 32000)}]: {text}"))

    def web(t, ip, path, status, method="GET"):
        web_inj.append((t, f'{ip} - - [{nginx_ts(t)}] "{method} {path} HTTP/1.1" {status} '
                           f'{rng.randint(150, 900)} "-" "{rng.choice(UAS)}"'))

    # --- SSH: перебор пароля (12 неудач за ~40 с); часть атакующих в итоге входит
    for i in range(k):
        ip = attacker_ip()
        t = start_time(200)
        for _ in range(12):
            t += rng.randint(1, 4)
            sshd(t, f"Failed password for {rng.choice(ATTACK_USERS)} from {ip} port {rng.randint(30000, 60000)} ssh2")
        truth["alerts"].append(["ssh_bruteforce", ip])
        if i % 5 == 0:
            t += rng.randint(30, 90)
            sshd(t, f"Accepted password for root from {ip} port {rng.randint(30000, 60000)} ssh2")
            truth["alerts"].append(["ssh_compromise", ip])

    # --- SSH: перебор имён пользователей (8 разных имён за ~40 с)
    for _ in range(k):
        ip = attacker_ip()
        t = start_time(200)
        for u in ENUM_USERS:
            t += rng.randint(2, 6)
            port = rng.randint(30000, 60000)
            sshd(t, f"Invalid user {u} from {ip} port {port}")
            sshd(t, f"Failed password for invalid user {u} from {ip} port {port} ssh2")
        truth["alerts"] += [["ssh_user_enum", ip], ["ssh_bruteforce", ip]]

    # --- SSH: «ловушки»: 4 неудачи за минуту — порог не пройден, алерта быть не должно
    for _ in range(k):
        ip = attacker_ip()
        t = start_time(100)
        for _ in range(4):
            t += rng.randint(3, 12)
            sshd(t, f"Failed password for root from {ip} port {rng.randint(30000, 60000)} ssh2")

    # --- Web: сканеры (60 запросов с 4xx за ~40 с)
    for _ in range(k):
        ip = attacker_ip()
        t = start_time(200)
        for _ in range(60):
            t += rng.randint(0, 1)
            web(t, ip, rng.choice(SCAN_PATHS) + str(rng.randint(0, 999)), rng.choice([403, 404, 404, 404]))
        truth["alerts"].append(["web_scan", ip])

    # --- Web: атаки по сигнатурам (2–3 запроса)
    for _ in range(k):
        ip = attacker_ip()
        t = start_time(100)
        for p in rng.sample(ATTACK_PATHS, rng.randint(2, 3)):
            t += rng.randint(1, 20)
            web(t, ip, p, rng.choice([200, 400, 404]))
        truth["alerts"].append(["web_attack", ip])

    # --- Web: «ловушки»: 15 ответов 4xx за 30 с — порог 20 не пройден
    for _ in range(k):
        ip = attacker_ip()
        t = start_time(100)
        for _ in range(15):
            t += rng.randint(0, 2)
            web(t, ip, f"/missing/{rng.randint(0, 9999)}.html", 404)

    # --- Web: всплески ошибок 502 (150 за одну минуту с разных адресов)
    spikes = max(2, k // 10)
    for _ in range(spikes):
        minute = (start_time(200) // 60) * 60
        for _ in range(150):
            web(minute + rng.randint(0, 59), f"198.18.{rng.randint(0, 11)}.{rng.randint(1, 250)}", "/api/v1/status", 502)
        truth["alerts"].append(["availability_spike", minute])

    auth_inj.sort(key=lambda x: x[0])
    web_inj.sort(key=lambda x: x[0])
    n_auth_benign = max(0, n - len(auth_inj))
    n_web_benign = max(0, n - len(web_inj))

    # --- фоновый трафик -----------------------------------------------------
    internal = [f"10.0.0.{i}" for i in range(2, 52)]
    users = ["kirill", "deploy", "backup", "monitor", "alex", "maria"]
    clients = [f"198.18.{a}.{b}" for a in range(0, 12) for b in range(1, 251)]  # 3000 клиентов
    paths = (["/", "/index.html", "/login", "/api/v1/status", "/api/v1/items", "/about", "/pricing", "/favicon.ico"]
             + [f"/static/img{i}.png" for i in range(40)] + [f"/static/app{i}.js" for i in range(10)]
             + [f"/blog/post-{i}" for i in range(60)])

    def benign_auth(t):
        r = rng.random()
        ts = syslog_ts(t)
        pid = rng.randint(1000, 32000)
        if r < 0.30:
            return f"{ts} srv-01 CRON[{pid}]: (root) CMD (/usr/local/bin/backup.sh)"
        if r < 0.50:
            return f"{ts} srv-01 systemd[1]: Started Session {rng.randint(1, 9999)} of User {rng.choice(users)}."
        if r < 0.70:
            return (f"{ts} srv-01 sshd[{pid}]: pam_unix(sshd:session): session opened for user "
                    f"{rng.choice(users)}(uid=1000) by (uid=0)")
        if r < 0.85:
            return (f"{ts} srv-01 sshd[{pid}]: Received disconnect from {rng.choice(internal)} "
                    f"port {rng.randint(30000, 60000)}:11: disconnected by user")
        if r < 0.995:
            return (f"{ts} srv-01 sshd[{pid}]: Accepted publickey for {rng.choice(users)} from "
                    f"{rng.choice(internal)} port {rng.randint(30000, 60000)} ssh2: RSA SHA256:abc")
        return (f"{ts} srv-01 sshd[{pid}]: Failed password for {rng.choice(users)} from "
                f"{rng.choice(internal)} port {rng.randint(30000, 60000)} ssh2")

    def benign_web(t):
        r = rng.random()
        status = 200 if r < 0.915 else 304 if r < 0.965 else 404 if r < 0.99 else rng.choice([500, 502, 503])
        return (f'{rng.choice(clients)} - - [{nginx_ts(t)}] "GET {rng.choice(paths)} HTTP/1.1" {status} '
                f'{rng.randint(150, 90000)} "-" "{rng.choice(UAS)}"')

    def write(path, inj, n_benign, maker):
        times = sorted(BASE + rng.randrange(SPAN) for _ in range(n_benign))
        j = 0
        with open(path, "w") as f:
            for t in times:
                while j < len(inj) and inj[j][0] <= t:
                    f.write(inj[j][1] + "\n")
                    j += 1
                f.write(maker(t) + "\n")
            while j < len(inj):
                f.write(inj[j][1] + "\n")
                j += 1

    write(os.path.join(args.out, "auth.log"), auth_inj, n_auth_benign, benign_auth)
    write(os.path.join(args.out, "access.log"), web_inj, n_web_benign, benign_web)

    truth["alerts"].sort()
    with open(os.path.join(args.out, "truth.json"), "w") as f:
        json.dump(truth, f, ensure_ascii=False)

    print(f"{args.out}: {n} строк в каждом файле, заложено {len(truth['alerts'])} эталонных алертов")


if __name__ == "__main__":
    main()
