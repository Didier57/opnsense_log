"""Generate an argon2 password hash for AUTH_PASSWORD_HASH.

Usage::

    python -m scripts.hash_password
"""
from __future__ import annotations

import getpass

from app.core.security import hash_password


def main() -> None:
    password = getpass.getpass("Password: ")
    print(hash_password(password))


if __name__ == "__main__":
    main()
