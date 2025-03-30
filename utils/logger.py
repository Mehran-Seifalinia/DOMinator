from logging import getLogger, Formatter, StreamHandler, DEBUG, INFO, WARNING, ERROR
from logging.handlers import RotatingFileHandler
from os import makedirs, path

# Define log directory and file
LOG_DIR = "logs"
LOG_FILE = path.join(LOG_DIR, "scanner.log")

# Ensure log directory exists
makedirs(LOG_DIR, exist_ok=True)

# Define log format and date format
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(module)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Create logger instance
logger = getLogger("dom_xss_scanner")
logger.setLevel(DEBUG)  # Set minimum logging level

# Create console handler (outputs INFO and higher to terminal)
console_handler = StreamHandler()
console_handler.setLevel(INFO)
console_handler.setFormatter(Formatter(LOG_FORMAT, DATE_FORMAT))

# Create file handler with log rotation (stores DEBUG and higher)
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
file_handler.setLevel(DEBUG)
file_handler.setFormatter(Formatter(LOG_FORMAT, DATE_FORMAT))

# Add handlers to logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def get_logger():
    """Returns the configured logger instance."""
    return logger
