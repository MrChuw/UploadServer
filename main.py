import argparse
import asyncio
import secrets

import uvicorn
from tortoise import Tortoise

from uploadserver.models import APIKey, UserRole
from uploadserver.utils import DATABASE_URL


async def create_key_cli(owner_name: str, role: UserRole, max_size_mb: float | None) -> None:
    await Tortoise.init(db_url=DATABASE_URL, modules={"models": ["uploadserver.models"]})
    await Tortoise.generate_schemas()
    generated_key = f"sk_{secrets.token_hex(24)}"
    max_size_bytes = int(max_size_mb * 1024 * 1024) if max_size_mb is not None else None
    try:
        key_obj = await APIKey.create(key=generated_key, owner=owner_name, role=role, max_upload_size=max_size_bytes)
        print(f"\nAPI Key Created:\nOwner: {key_obj.owner}\nRole: {key_obj.role.value}\nKey: {key_obj.key}\n")
    finally:
        await Tortoise.close_connections()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Server API & Management CLI")
    parser.add_index = False
    subparsers = parser.add_subparsers(dest="command", help="Available execution options")
    subparsers.add_parser("run", help="Start the FastAPI service application")

    key_parser = subparsers.add_parser("create-key", help="Provision a new credential token")
    key_parser.add_argument("--owner", type=str, required=True)
    key_parser.add_argument("--role", type=UserRole, choices=list(UserRole), default=UserRole.NORMAL)
    key_parser.add_argument("--max-size-mb", type=float, default=None)

    args = parser.parse_args()
    if args.command == "create-key":
        asyncio.run(create_key_cli(args.owner, args.role, args.max_size_mb))
    elif args.command == "run" or args.command is None:
        uvicorn.run(app="uploadserver:app", host="0.0.0.0", port=8000, workers=4, reload=False)
