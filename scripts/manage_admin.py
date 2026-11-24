"""Create the admin password hash (for VIGIL_ADMIN_PASSWORD_HASH) or insert an admin user.

    python scripts/manage_admin.py hash                 # prompts, prints a scrypt hash
    python scripts/manage_admin.py create --username a  # prompts, stores in the database

Passwords are read with getpass (never from argv or the environment).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import select

from vigilsiem.core.db import Database
from vigilsiem.models.orm import AdminUser
from vigilsiem.security.passwords import hash_password

MIN_LEN = 12


def _prompt() -> str:
    first = getpass.getpass("Password: ")
    if len(first) < MIN_LEN:
        print(f"error: use at least {MIN_LEN} characters", file=sys.stderr)
        raise SystemExit(2)
    if first != getpass.getpass("Repeat: "):
        print("error: passwords differ", file=sys.stderr)
        raise SystemExit(2)
    return first


async def _create(username: str, pw_hash: str) -> None:
    db = Database(os.environ.get("VIGIL_DATABASE_URL", "sqlite+aiosqlite:///./data/vigilsiem.db"))
    await db.create_all()
    try:
        async with db.session() as session:
            row = await session.scalar(select(AdminUser).where(AdminUser.username == username))
            if row is None:
                session.add(AdminUser(username=username, password_hash=pw_hash))
            else:
                row.password_hash = pw_hash
    finally:
        await db.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description="VigilSIEM admin helper")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hash")
    sub.add_parser("create").add_argument("--username", required=True)
    args = parser.parse_args()
    pw_hash = hash_password(_prompt())
    if args.command == "hash":
        print(pw_hash)
    else:
        asyncio.run(_create(args.username, pw_hash))
        print(f"admin '{args.username}' saved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
