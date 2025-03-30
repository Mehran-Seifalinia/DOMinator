from logging import getLogger, Formatter, StreamHandler, INFO, DEBUG
from logging.handlers import RotatingFileHandler
from os import makedirs, path, getenv
from sys import stderr

# Configuration
LOG_DIR = "logs"
LOG_FILE = path.join(LOG_DIR, "scanner.log")
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(module)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_BYTES = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT = 5

# Validate and set log level
VALID_LOG_LEVELS = {"DEBUG": DEBUG, "INFO": INFO, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
LOG_LEVEL = getenv("LOG_LEVEL", "DEBUG").upper()
LOG_LEVEL = VALID_LOG_LEVELS.get(LOG_LEVEL, DEBUG)  # Default to DEBUG if invalid

# Ensure log directory exists
try:
    makedirs(LOG_DIR, exist_ok=True)
except OSError as e:
    print(f"Failed to create log directory: {e}", file=stderr)
    raise

# Create logger
logger = getLogger(__name__)
logger.setLevel(LOG_LEVEL)

# Remove existing handlers
logger.handlers.clear()

try:
    # Console handler (set to INFO to avoid excessive DEBUG logs)
    console_handler = StreamHandler()
    console_handler.setLevel(INFO)
    console_handler.setFormatter(Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(console_handler)

    # File handler
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(Formatter(LOG_FORMAT, DATE_FORMAT))
        logger.addHandler(file_handler)
    except IOError as e:
        logger.error(f"Failed to setup file logging: {e}")

except Exception as e:
    print(f"Failed to setup logging: {e}", file=stderr)
    raise

def get_logger():
    """Returns the configured logger instance."""
    return logger
