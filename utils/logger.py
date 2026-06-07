"""
Logger Module
Provides logging functionality for the DOM XSS scanner.
"""

from logging import getLogger, Formatter, StreamHandler, INFO, DEBUG, WARNING, ERROR, CRITICAL, Logger
from logging.handlers import RotatingFileHandler
from os import makedirs, path, getenv
from sys import stderr
from typing import Optional, Tuple

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
    "WARNING": WARNING,
    "ERROR": ERROR,
    "CRITICAL": CRITICAL
}
LOG_LEVEL: int = VALID_LOG_LEVELS.get(getenv("LOG_LEVEL", "DEBUG").upper(), DEBUG)

def setup_handlers() -> Tuple[StreamHandler, Optional[RotatingFileHandler]]:
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
        makedirs(LOG_DIR, exist_ok=True)
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8"
        )
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(formatter)
    except (IOError, OSError) as e:
        print(f"Failed to setup file logging: {e}", file=stderr)
        file_handler = None
    
    return console_handler, file_handler

# Initialize logging infrastructure
_console_handler, _file_handler = setup_handlers()

# Configure root logger with handlers (once)
_root_logger = getLogger()
_root_logger.setLevel(LOG_LEVEL)
_root_logger.addHandler(_console_handler)
if _file_handler:
    _root_logger.addHandler(_file_handler)

def get_logger(name: Optional[str] = None) -> Logger:
    """
    Get a configured logger instance.
    
    Args:
        name (Optional[str]): Name of the logger. If None, returns root logger.
        
    Returns:
        Logger: Configured logger instance
        
    Note:
        Handlers are attached to the root logger only. Child loggers propagate to root.
    """
    logger = getLogger(name)
    logger.setLevel(LOG_LEVEL)
    return logger

def set_console_level(level: int) -> None:
    """
    Set the logging level for the console handler.
    
    Args:
        level (int): Logging level (e.g., logging.WARNING, logging.ERROR)
    """
    _console_handler.setLevel(level)
