import logging
import json
import uuid
from datetime import datetime
from typing import Any


class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to log records"""

    def __init__(self):
        super().__init__()
        self.correlation_id = None

    def filter(self, record):
        record.correlation_id = self.correlation_id or str(uuid.uuid4())[:8]
        return True


class JSONFormatter(logging.Formatter):
    """JSON log formatter"""

    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", "unknown"),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


def setup_logging():
    """Configure logging for the application"""
    correlation_filter = CorrelationIdFilter()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JSONFormatter())
    console_handler.addFilter(correlation_filter)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)

    # Set levels for specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)

    return correlation_filter