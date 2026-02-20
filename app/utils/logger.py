"""Logging helper: configures rotating logs directory."""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(name: str = "novavault", logs_dir: str | Path = "./logs", level=logging.INFO):
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        fh = RotatingFileHandler(logs_dir / f"{name}.log", maxBytes=5_000_000, backupCount=5)
        fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger
