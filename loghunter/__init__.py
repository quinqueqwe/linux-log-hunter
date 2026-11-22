"""loghunter: поиск атак в Linux-логах (sshd, nginx)."""
from .auth import analyze_auth
from .web import analyze_nginx

__all__ = ["analyze_auth", "analyze_nginx"]
