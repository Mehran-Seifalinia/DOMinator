"""
Logger Module
Provides logging functionality for the DOM XSS scanner.
"""

from logging import getLogger, Formatter, StreamHandler, INFO, DEBUG, Logger
from logging.handlers import RotatingFileHandler
from os import makedirs, path, getenv
from sys import stderr
from typing import Optional

# Configuration
LOG_DIR: str = "logs"
LOG_FILE: str = path.join(LOG_DIR, "scanner.log")
LOG_FORMAT: str = "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
MAX_BYTES: int = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT: int = 5

# Validate and set log level
VALID_LOG_LEVELS: dict = {
    "DEBUG": DEBUG,
    "INFO": INFO,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50
}
LOG_LEVEL: int = VALID_LOG_LEVELS.get(getenv("LOG_LEVEL", "DEBUG").upper(), DEBUG)

def setup_log_directory() -> None:
    """
    Create the log directory if it doesn't exist.
    
    Raises:
        OSError: If directory creation fails
    """
    try:
        makedirs(LOG_DIR, exist_ok=True)
    except OSError as e:
        print(f"Failed to create log directory: {e}", file=stderr)
        raise

def setup_handlers() -> tuple:
    """
    Set up logging handlers.
    
    Returns:
        tuple: (console_handler, file_handler)
        
    Note:
        The file handler may be None if file logging setup fails.
    """
    formatter = Formatter(LOG_FORMAT, DATE_FORMAT)
    
    console_handler = StreamHandler()
    console_handler.setLevel(INFO)
    console_handler.setFormatter(formatter)
    
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8"
        )
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(formatter)
    except IOError as e:
        print(f"Failed to setup file logging: {e}", file=stderr)
        file_handler = None
    
    return console_handler, file_handler

# Initialize logging infrastructure
setup_log_directory()
_console_handler, _file_handler = setup_handlers()

def get_logger(name: Optional[str] = None) -> Logger:
    """
    Get a configured logger instance.
    
    Args:
        name (Optional[str]): Name of the logger. If None, uses 'global'
        
    Returns:
        Logger: Configured logger instance
        
    Note:
        This function ensures that handlers are only added once to each logger.
    """
    logger_name = name if name else "global"
    logger = getLogger(logger_name)
    logger.setLevel(LOG_LEVEL)

    if not logger.handlers:
        logger.addHandler(_console_handler)
        if _file_handler:
            logger.addHandler(_file_handler)

    return logger
