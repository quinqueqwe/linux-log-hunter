"""Пороги детектов. Один и тот же набор используют и v1 (naive), и v2 (loghunter),
чтобы сравнение скорости было честным: обе версии находят одно и то же."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    bf_n: int = 5               # неудачных входов SSH с одного IP...
    bf_window: int = 60         # ...за столько секунд = подбор пароля
    enum_n: int = 5             # разных неизвестных имён пользователей...
    enum_window: int = 60       # ...за столько секунд = перебор имён
    compromise_window: int = 600  # успешный вход после подбора не позже, чем через N с
    scan_n: int = 20            # ответов 4xx одному клиенту...
    scan_window: int = 60       # ...за столько секунд = сканирование
    spike_n: int = 100          # ответов 5xx за одну минуту = всплеск ошибок


DEFAULT = Config()

# Что считаем признаком атаки в строке запроса (в нижнем регистре).
WEB_SIGNATURES = (
    "../", "..%2f", "/etc/passwd", "union select", "union%20select", "<script",
    "/.env", "/.git/", "cmd.exe", "base64_decode", "${jndi:",
)

MITRE = {
    "ssh_bruteforce": "T1110.001",
    "ssh_user_enum": "T1110",
    "ssh_compromise": "T1078",
    "web_scan": "T1595.002",
    "web_attack": "T1190",
    "availability_spike": "-",
}

SEVERITY = {
    "ssh_compromise": "CRITICAL",
    "ssh_bruteforce": "HIGH",
    "web_attack": "HIGH",
    "availability_spike": "HIGH",
    "ssh_user_enum": "MEDIUM",
    "web_scan": "MEDIUM",
}
