"""
logger.py — Centralised logging for the Attack Simulation Toolkit.

Provides a pre-configured logger that writes:
  • To the console (coloured, human-friendly)
  • To a rotating log file in the ``logs/`` directory

Format:  TIMESTAMP | LEVEL | MODULE | MESSAGE
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from network_sim.config import LOG_DIR, LOG_FILE


def get_logger(module_name: str) -> logging.Logger:
    """Return a logger named *module_name* with console + file handlers.

    Calling this multiple times with the same *module_name* is safe — Python's
    logging module deduplicates handlers automatically when using ``getLogger``.
    """
    logger = logging.getLogger(module_name)

    # Avoid adding handlers more than once when get_logger is called repeatedly
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── Console handler (INFO and above) ──────────────────────────────────
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    # ── File handler (DEBUG and above, rotating 5 MB × 3 backups) ─────────
    os.makedirs(LOG_DIR, exist_ok=True)
    file_path = os.path.join(LOG_DIR, LOG_FILE)
    file_handler = RotatingFileHandler(
        file_path, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    return logger
