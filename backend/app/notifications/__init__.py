"""Notification channels (email/SMTP for now)."""
from .mailer import send_email, send_test_email
from .store import get_smtp_settings, update_smtp_settings

__all__ = ["send_email", "send_test_email", "get_smtp_settings", "update_smtp_settings"]
