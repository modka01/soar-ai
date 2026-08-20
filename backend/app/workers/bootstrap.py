"""One-shot bootstrap: run migrations' companion seeding.

Executed by the Helm pre-upgrade hook after ``alembic upgrade head``.
"""

from __future__ import annotations

import asyncio
import sys

from app.core.logging import configure_logging, get_logger
from app.db.session import dispose_engine, session_scope
from app.services.seed import seed_all

logger = get_logger(__name__)


async def _run() -> dict[str, int]:
    async with session_scope() as db:
        return await seed_all(db)


def main() -> None:
    configure_logging()
    try:
        result = asyncio.run(_run())
    except Exception as exc:
        logger.exception("bootstrap_failed", error=str(exc))
        sys.exit(1)
    finally:
        asyncio.run(dispose_engine())
    logger.info("bootstrap_complete", **result)


if __name__ == "__main__":
    main()
