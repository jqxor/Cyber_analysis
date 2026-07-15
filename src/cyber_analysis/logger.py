import logging
import sys
from pathlib import Path

LOGGER_NAME = "cyber_analysis"

_initialized = False


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    global _initialized
    logger = logging.getLogger(name)

    if not _initialized:
        logger.setLevel(logging.DEBUG)

        fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console.setFormatter(fmt)
        logger.addHandler(console)

        _initialized = True

    return logger


def setup_file_logging(log_dir: Path, name: str = LOGGER_NAME) -> logging.Logger:
    logger = get_logger(name)
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_dir / "analysis.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)
    return logger
