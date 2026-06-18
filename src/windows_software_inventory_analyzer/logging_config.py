from __future__ import annotations

import logging
from pathlib import Path

from .models import LoggingConfig


def configure_logging(config: LoggingConfig) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]

    if config.log_to_file:
        log_dir = Path(config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / "app.log", encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, config.level, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=handlers,
    )
