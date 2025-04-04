from logging import getLogger, Formatter, StreamHandler, INFO, DEBUG
from logging.handlers import RotatingFileHandler
from os import makedirs, path, getenv
from sys import stderr

# Configuration
LOG_DIR = "logs"
LOG_FILE = path.join(LOG_DIR, "scanner.log")
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_BYTES = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT = 5

# Validate and set log level
VALID_LOG_LEVELS = {"DEBUG": DEBUG, "INFO": INFO, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
LOG_LEVEL = getenv("LOG_LEVEL", "DEBUG").upper()
LOG_LEVEL = VALID_LOG_LEVELS.get(LOG_LEVEL, DEBUG)

# Ensure log directory exists
try:
    makedirs(LOG_DIR, exist_ok=True)
except OSError as e:
    print(f"Failed to create log directory: {e}", file=stderr)
    raise

# Shared formatter and handlers (only created once)
_formatter = Formatter(LOG_FORMAT, DATE_FORMAT)

_console_handler = StreamHandler()
_console_handler.setLevel(INFO)
_console_handler.setFormatter(_formatter)

try:
    _file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    _file_handler.setLevel(LOG_LEVEL)
    _file_handler.setFormatter(_formatter)
except IOError as e:
    print(f"Failed to setup file logging: {e}", file=stderr)
    _file_handler = None

def get_logger(name=None):
    """Returns a configured logger instance."""
    logger_name = name if name else "global"
    logger = getLogger(logger_name)
    logger.setLevel(LOG_LEVEL)

    # Add handlers only if they haven't been added already
    if not logger.handlers:
        logger.addHandler(_console_handler)
        if _file_handler:
            logger.addHandler(_file_handler)

    return logger
