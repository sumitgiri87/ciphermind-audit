"""
Logging configuration for CipherMind audit tool.

Sets up a consistent format across all modules.
Call configure_logging() once at CLI startup.
"""

import logging
import sys


def configure_logging(verbose: bool = False) -> None:
    """
    Configure root logger.

    Args:
        verbose: if True, set level to DEBUG; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%H:%M:%S"

    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt=datefmt,
        stream=sys.stderr,
    )

    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
