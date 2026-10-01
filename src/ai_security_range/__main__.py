"""Run the service: ``python -m ai_security_range``."""

from __future__ import annotations

import os


def main() -> None:
    import uvicorn

    uvicorn.run(
        "ai_security_range.app:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=bool(os.getenv("RELOAD")),
        server_header=False,  # don't advertise the server stack
        limit_concurrency=int(os.getenv("LIMIT_CONCURRENCY", "100")),  # shed load with 503s
        timeout_keep_alive=5,
    )


if __name__ == "__main__":
    main()
