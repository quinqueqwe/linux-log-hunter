"""Запуск: python -m loghunter --auth /var/log/auth.log --nginx /var/log/nginx/access.log"""
import argparse
import datetime
import os
import sys
import time

from .auth import analyze_auth
from .report import enrich, format_text, send_telegram, write_json
from .web import analyze_nginx


def main(argv=None):
    ap = argparse.ArgumentParser(prog="loghunter", description="Поиск атак в auth.log и nginx access.log")
    ap.add_argument("--auth", help="путь к auth.log (sshd)")
    ap.add_argument("--nginx", help="путь к nginx access.log (формат combined)")
    ap.add_argument("--year", type=int, default=datetime.datetime.now(datetime.timezone.utc).year,
                    help="год для auth.log (в syslog его нет), по умолчанию текущий")
    ap.add_argument("--json", help="сохранить алерты в JSON")
    ap.add_argument("--telegram", action="store_true",
                    help="отправить итог в Telegram (переменные окружения TG_TOKEN и TG_CHAT_ID)")
    args = ap.parse_args(argv)

    if not args.auth and not args.nginx:
        ap.error("укажите хотя бы один файл: --auth или --nginx")

    started = time.perf_counter()
    alerts = []
    if args.auth:
        alerts += analyze_auth(args.auth, args.year)
    if args.nginx:
        alerts += analyze_nginx(args.nginx)
    alerts = enrich(alerts)
    elapsed = time.perf_counter() - started

    print(format_text(alerts))
    print(f"\nАлертов: {len(alerts)}, время анализа: {elapsed:.2f} с", file=sys.stderr)

    if args.json:
        write_json(alerts, args.json)
    if args.telegram and alerts:
        token, chat = os.environ.get("TG_TOKEN"), os.environ.get("TG_CHAT_ID")
        if not token or not chat:
            ap.error("для --telegram задайте TG_TOKEN и TG_CHAT_ID")
        send_telegram(format_text(alerts), token, chat)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
