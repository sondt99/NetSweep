#!/usr/bin/env python3
"""
Professional error handling system for NetSweep
Centralized error management and logging
"""

import logging
import sys
import traceback
from enum import Enum
from typing import Optional, Callable, Any, Dict, List
from functools import wraps
from pathlib import Path
import time


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NetSweepError(Exception):
    """Base exception class for NetSweep"""

    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 original_error: Optional[Exception] = None):
        self.message = message
        self.severity = severity
        self.original_error = original_error
        super().__init__(self.message)


class NetworkError(NetSweepError):
    """Network-related errors"""

    def __init__(self, message: str, target: Optional[str] = None, **kwargs):
        self.target = target
        super().__init__(message, **kwargs)


class ConfigurationError(NetSweepError):
    """Configuration-related errors"""

    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        self.config_key = config_key
        super().__init__(message, **kwargs)


class SecurityError(NetSweepError):
    """Security-related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, severity=ErrorSeverity.HIGH, **kwargs)


class PermissionError(NetSweepError):
    """Permission-related errors"""

    def __init__(self, message: str, operation: Optional[str] = None, **kwargs):
        self.operation = operation
        super().__init__(message, severity=ErrorSeverity.HIGH, **kwargs)


class ErrorHandler:
    """Professional error handling and logging manager"""

    def __init__(self, log_file: Optional[str] = None, log_level: int = logging.INFO):
        """Initialize error handler

        Args:
            log_file: Path to log file (optional)
            log_level: Logging level (default: INFO)
        """
        self.log_file = log_file
        self.log_level = log_level
        self.error_counts: Dict[str, int] = {}
        self.critical_errors: List[Dict[str, Any]] = []
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure logging format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Setup root logger
        root_logger = logging.getLogger('NetSweep')
        root_logger.setLevel(self.log_level)
        root_logger.handlers.clear()  # Clear existing handlers

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        # File handler
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)  # More verbose in file
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

        self.logger = root_logger

    def handle_error(self, error: Exception, context: str = "",
                    reraise: bool = False) -> bool:
        """Handle an error with professional logging

        Args:
            error: The exception to handle
            context: Additional context information
            reraise: Whether to reraise the exception

        Returns:
            True if error was handled, False if it should be re-raised
        """
        error_type = type(error).__name__
        error_msg = str(error)
        context_str = f" (Context: {context})" if context else ""

        # Count errors
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        # Log the error
        if isinstance(error, NetSweepError):
            log_level = {
                ErrorSeverity.LOW: logging.WARNING,
                ErrorSeverity.MEDIUM: logging.ERROR,
                ErrorSeverity.HIGH: logging.ERROR,
                ErrorSeverity.CRITICAL: logging.CRITICAL
            }.get(error.severity, logging.ERROR)

            self.logger.log(log_level,
                          f"{error_type} (Severity: {error.severity.value}): "
                          f"{error_msg}{context_str}")

            # Track critical errors
            if error.severity == ErrorSeverity.CRITICAL:
                self.critical_errors.append({
                    'timestamp': time.time(),
                    'error_type': error_type,
                    'message': error_msg,
                    'context': context,
                    'traceback': traceback.format_exc()
                })

        else:
            self.logger.error(f"Unexpected {error_type}: {error_msg}{context_str}")

        # Log full traceback for debugging
        self.logger.debug(f"Full traceback:\n{traceback.format_exc()}")

        # Decide whether to reraise
        if reraise or isinstance(error, (SecurityError, PermissionError)):
            raise error

        return True

    def log_info(self, message: str) -> None:
        """Log informational message"""
        self.logger.info(message)

    def log_warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)

    def log_debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all errors encountered

        Returns:
            Dictionary containing error statistics
        """
        return {
            'total_errors': sum(self.error_counts.values()),
            'error_types': dict(self.error_counts),
            'critical_errors_count': len(self.critical_errors),
            'critical_errors': self.critical_errors.copy()
        }

    def reset_error_counts(self) -> None:
        """Reset error counters"""
        self.error_counts.clear()
        self.critical_errors.clear()


# Global error handler instance
_error_handler = None


def get_error_handler(log_file: Optional[str] = None) -> ErrorHandler:
    """Get global error handler instance

    Args:
        log_file: Path to log file (optional)

    Returns:
        ErrorHandler instance
    """
    global _error_handler
    if _error_handler is None:
        log_file = log_file or "logs/netsweep.log"
        _error_handler = ErrorHandler(log_file)
    return _error_handler


def handle_errors(error_types: Optional[List[type]] = None,
                 default_return: Any = None,
                 log_context: str = "",
                 reraise: bool = False) -> Callable:
    """Decorator for standardized error handling

    Args:
        error_types: List of exception types to catch (None = all)
        default_return: Value to return on error
        log_context: Context for logging
        reraise: Whether to reraise exceptions

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handler = get_error_handler()

                # Check if this error type should be caught
                if error_types and not any(isinstance(e, error_type) for error_type in error_types):
                    raise e

                context = log_context or f"{func.__module__}.{func.__name__}"
                handler.handle_error(e, context, reraise)

                return default_return
        return wrapper
    return decorator


def safe_execute(func: Callable, *args, default_return: Any = None,
                log_context: str = "", **kwargs) -> Any:
    """Safely execute a function with error handling

    Args:
        func: Function to execute
        *args: Function arguments
        default_return: Value to return on error
        log_context: Context for logging
        **kwargs: Function keyword arguments

    Returns:
        Function result or default_return on error
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        handler = get_error_handler()
        context = log_context or f"{func.__module__}.{func.__name__}"
        handler.handle_error(e, context)
        return default_return


# Convenience functions for common operations
def log_info(message: str) -> None:
    """Log informational message"""
    get_error_handler().log_info(message)


def log_warning(message: str) -> None:
    """Log warning message"""
    get_error_handler().log_warning(message)


def log_debug(message: str) -> None:
    """Log debug message"""
    get_error_handler().log_debug(message)


def get_error_summary() -> Dict[str, Any]:
    """Get summary of all errors encountered"""
    return get_error_handler().get_error_summary()


if __name__ == "__main__":
    # Example usage and testing
    import argparse

    parser = argparse.ArgumentParser(description="NetSweep Error Handler Test")
    parser.add_argument("--test-errors", action="store_true", help="Test error handling")
    parser.add_argument("--log-file", help="Log file path", default="logs/test.log")

    args = parser.parse_args()

    if args.test_errors:
        handler = get_error_handler(args.log_file)

        # Test different types of errors
        try:
            raise NetworkError("Test network error", target="192.168.1.1")
        except NetworkError as e:
            handler.handle_error(e, "Testing network error handling")

        try:
            raise ConfigurationError("Test config error", config_key="timeout")
        except ConfigurationError as e:
            handler.handle_error(e, "Testing configuration error")

        try:
            raise SecurityError("Test security error")
        except SecurityError as e:
            handler.handle_error(e, "Testing security error handling")

        # Test decorator
        @handle_errors(default_return="Error handled", log_context="Test function")
        def test_function(should_fail: bool = False):
            if should_fail:
                raise ValueError("Test function error")
            return "Success"

        result = test_function(should_fail=True)
        print(f"Function result: {result}")

        # Show error summary
        summary = handler.get_error_summary()
        print(f"\nError Summary: {summary}")