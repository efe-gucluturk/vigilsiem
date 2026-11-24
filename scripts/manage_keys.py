"""Generate / rotate / revoke / list agent API keys.

Usage:
    python scripts/manage_keys.py create  --name web-01
    python scripts/manage_keys.py rotate  --name web-01
    python scripts/manage_keys.py revoke  --name web-01
    python scripts/manage_keys.py list

The plaintext key is printed exactly once and is never stored (only its SHA-256).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys

from sqlalchemy import select

from vigilsiem.core.db import Database
from vigilsiem.models.orm import ApiKey
from vigilsiem.security.apikeys import generate_key

_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DEFAULT_URL = "sqlite+aiosqlite:///./data/vigilsiem.db"


async def _run(args: argparse.Namespace) -> int:
    db = Database(os.environ.get("VIGIL_DATABASE_URL", _DEFAULT_URL))
    await db.create_all()
    try:
        async with db.session() as session:
            if args.command == "list":
                for k in (await session.scalars(select(ApiKey).order_by(ApiKey.id))).all():
                    state = "revoked" if k.revoked else "active"
                    print(f"{k.name:<24} vsk_{k.key_prefix}...  {state}  {k.created_at:%Y-%m-%d}")
                return 0

            if not _NAME.fullmatch(args.name or ""):
                print("error: --name must match [A-Za-z0-9._-]{1,64}", file=sys.stderr)
                return 2
            existing = await session.scalar(select(ApiKey).where(ApiKey.name == args.name))

            if args.command == "revoke":
                if existing is None:
                    print("error: no such key", file=sys.stderr)
                    return 1
                existing.revoked = True
                print(f"revoked {args.name}")
                return 0

            if args.command == "create" and existing is not None:
                print("error: name exists; use 'rotate'", file=sys.stderr)
                return 1
            if args.command == "rotate" and existing is None:
                print("error: no such key; use 'create'", file=sys.stderr)
                return 1

            new = generate_key()
            if existing is None:
                session.add(ApiKey(name=args.name, key_prefix=new.prefix, key_hash=new.key_hash))
            else:
                existing.key_prefix = new.prefix
                existing.key_hash = new.key_hash
                existing.revoked = False
            print(f"API key for '{args.name}' (store it now; it cannot be shown again):")
            print(new.plaintext)
            return 0
    finally:
        await db.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage VigilSIEM agent API keys")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "rotate", "revoke"):
        sub.add_parser(name).add_argument("--name", required=True)
    sub.add_parser("list")
    return asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
