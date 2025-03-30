from logging import getLogger, Formatter, StreamHandler, DEBUG, INFO
from logging.handlers import RotatingFileHandler
from os import makedirs, path
from sys import stderr

# Define log directory and file
LOG_DIR = "logs"
LOG_FILE = path.join(LOG_DIR, "scanner.log")
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(module)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_BYTES = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT = 5

# Ensure log directory exists
try:
    makedirs(LOG_DIR, exist_ok=True)
except OSError as e:
    print(f"Failed to create log directory: {e}", file=stderr)
    raise

# Create logger instance
logger = getLogger("dom_xss_scanner")
logger.setLevel(DEBUG)

# Remove existing handlers to prevent duplicates
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
    handler.close()

# Create console handler (outputs INFO and higher to terminal)
console_handler = StreamHandler()
console_handler.setLevel(INFO)
console_handler.setFormatter(Formatter(LOG_FORMAT, DATE_FORMAT))

# Create file handler with log rotation (stores DEBUG and higher)
try:
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8")
    file_handler.setLevel(DEBUG)
    file_handler.setFormatter(Formatter(LOG_FORMAT, DATE_FORMAT))
except IOError as e:
    print(f"Failed to setup file logging: {e}", file=stderr)
    raise

# Add handlers to logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def get_logger():
    """Returns the configured logger instance."""
    return logger
