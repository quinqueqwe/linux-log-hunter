"""Форматирование алертов: текст для консоли, JSON-файл, отправка в Telegram."""
import datetime
import json
import urllib.parse
import urllib.request

from .config import MITRE, SEVERITY

_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def enrich(alerts):
    """Добавляет к алертам важность и технику MITRE ATT&CK, сортирует по важности и времени."""
    for a in alerts:
        a["severity"] = SEVERITY.get(a["type"], "LOW")
        a["mitre"] = MITRE.get(a["type"], "-")
    return sorted(alerts, key=lambda a: (_ORDER[a["severity"]], a["first_seen"]))


def format_text(alerts):
    if not alerts:
        return "Подозрительной активности не найдено."
    lines = []
    for a in alerts:
        who = f"минута {_iso(a['key'])}" if a["type"] == "availability_spike" else a["key"]
        extra = f", событий: {a['count']}" if a.get("count") else ""
        lines.append(f"[{a['severity']}] {a['type']} ({a['mitre']}) {who} с {_iso(a['first_seen'])}{extra}")
    return "\n".join(lines)


def write_json(alerts, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)


def send_telegram(text, token, chat_id, timeout=10):
    """Отправляет текст в Telegram-чат. Токен и chat_id передаются снаружи (переменные окружения)."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:4000]}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=timeout) as resp:
        return resp.status == 200
