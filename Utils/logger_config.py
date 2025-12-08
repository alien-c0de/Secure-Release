"""
Centralized Logging Configuration for Secure Release Tool
This module provides a unified logging system with file rotation and module-specific loggers.
"""

import logging
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime
import yaml

# Global configuration cache
_logging_config = None
_loggers_cache = {}


def load_logging_config(config_path="config.yaml"):
    """Load logging configuration from YAML file."""
    global _logging_config
    
    if _logging_config is not None:
        return _logging_config
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            _logging_config = config.get('logging', {})
            return _logging_config
    except Exception as e:
        # Fallback configuration if file read fails
        print(f"Warning: Could not load logging config: {e}")
        _logging_config = {
            'enabled': False,
            'level': 'INFO',
            'log_dir': './logs',
            'max_file_size_mb': 10,
            'backup_count': 5,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            'date_format': '%Y-%m-%d %H:%M:%S'
        }
        return _logging_config


def setup_log_directory(log_dir):
    """Create logs directory if it doesn't exist."""
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    return log_path


def get_logger(module_name, config_path="config.yaml"):
    """
    Get or create a logger for the specified module.
    
    Args:
        module_name: Name of the module requesting the logger
        config_path: Path to config.yaml file
        
    Returns:
        logging.Logger: Configured logger instance
    """
    global _loggers_cache
    
    # Return cached logger if exists
    if module_name in _loggers_cache:
        return _loggers_cache[module_name]
    
    # Load logging configuration
    log_config = load_logging_config(config_path)
    
    # Create logger
    logger = logging.getLogger(module_name)
    logger.handlers.clear()  # Clear any existing handlers
    logger.propagate = False  # Prevent propagation to root logger
    
    # Check if logging is enabled
    if not log_config.get('enabled', False):
        # Disable logging by setting to CRITICAL+1 (effectively silent)
        logger.setLevel(logging.CRITICAL + 1)
        logger.addHandler(logging.NullHandler())
        _loggers_cache[module_name] = logger
        return logger
    
    # Configure log level
    log_level = getattr(logging, log_config.get('level', 'INFO').upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Setup log directory
    log_dir = setup_log_directory(log_config.get('log_dir', './logs'))
    
    # Get configuration values
    max_bytes = log_config.get('max_file_size_mb', 10) * 1024 * 1024  # Convert MB to bytes
    backup_count = log_config.get('backup_count', 5)
    log_format = log_config.get('format', 
                                 '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
    date_format = log_config.get('date_format', '%Y-%m-%d %H:%M:%S')
    
    # Create formatter
    formatter = logging.Formatter(log_format, datefmt=date_format)
    
    # Main application log (all modules)
    main_log_file = log_dir / f"secure_release_{datetime.now().strftime('%Y-%m-%d')}.log"
    main_handler = RotatingFileHandler(
        main_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    main_handler.setFormatter(formatter)
    main_handler.setLevel(log_level)
    logger.addHandler(main_handler)
    
    # Module-specific log file
    module_log_file = log_dir / f"{module_name.replace('.', '_')}_{datetime.now().strftime('%Y-%m-%d')}.log"
    module_handler = RotatingFileHandler(
        module_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    module_handler.setFormatter(formatter)
    module_handler.setLevel(log_level)
    logger.addHandler(module_handler)
    
    # Error-only log file (for all modules)
    error_log_file = log_dir / f"errors_{datetime.now().strftime('%Y-%m-%d')}.log"
    error_handler = RotatingFileHandler(
        error_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)  # Only ERROR and CRITICAL
    logger.addHandler(error_handler)
    
    # Cache the logger
    _loggers_cache[module_name] = logger
    
    return logger


def log_execution_time(logger, operation_name):
    """
    Decorator to log execution time of functions.
    
    Usage:
        @log_execution_time(logger, "dependency_scan")
        async def scan(config):
            # function code
    """
    def decorator(func):
        import functools
        import time
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            logger.info(f"Starting {operation_name}")
            try:
                result = await func(*args, **kwargs)
                elapsed = time.perf_counter() - start_time
                logger.info(f"Completed {operation_name} in {elapsed:.2f} seconds")
                return result
            except Exception as e:
                elapsed = time.perf_counter() - start_time
                logger.error(f"Failed {operation_name} after {elapsed:.2f} seconds: {str(e)}", exc_info=True)
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            logger.info(f"Starting {operation_name}")
            try:
                result = func(*args, **kwargs)
                elapsed = time.perf_counter() - start_time
                logger.info(f"Completed {operation_name} in {elapsed:.2f} seconds")
                return result
            except Exception as e:
                elapsed = time.perf_counter() - start_time
                logger.error(f"Failed {operation_name} after {elapsed:.2f} seconds: {str(e)}", exc_info=True)
                raise
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def clear_logger_cache():
    """Clear the logger cache. Useful for testing or reconfiguration."""
    global _loggers_cache, _logging_config
    _loggers_cache.clear()
    _logging_config = None


# Example usage in modules:
if __name__ == "__main__":
    # Test the logging system
    logger = get_logger("test_module")
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    # Test with exception
    try:
        raise ValueError("Test exception")
    except Exception as e:
        logger.error("Caught an exception", exc_info=True)
