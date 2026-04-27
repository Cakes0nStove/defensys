import logging

from config import LOG_LEVEL

# Prevents logging from being configured more than once.

_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
        # Creates or returns a named logger.

    global _CONFIGURED
    if not _CONFIGURED:
                # Uses LOG_LEVEL from config, defaults to ERROR if invalid.

        level = getattr(logging, LOG_LEVEL, logging.ERROR)
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        )
        _CONFIGURED = True
    return logging.getLogger(name)
