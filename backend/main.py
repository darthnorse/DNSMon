import logging
import os
from logging.handlers import RotatingFileHandler
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configure dedicated memory logger to file (with fallback if permissions fail)
LOGS_DIR = '/app/logs'
memory_logger = logging.getLogger('dnsmon.memory')
memory_logger.setLevel(logging.INFO)

try:
    os.makedirs(LOGS_DIR, exist_ok=True)
    memory_handler = RotatingFileHandler(
        os.path.join(LOGS_DIR, 'memory.log'),
        maxBytes=10 * 1024 * 1024,  # 10 MB per file
        backupCount=5,  # Keep 5 backup files (50 MB total)
    )
    memory_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    memory_logger.addHandler(memory_handler)
    memory_logger.propagate = False  # Don't send to root logger (avoid duplicate docker logs)
    logger.info("Memory logging to file enabled: /app/logs/memory.log")
except (PermissionError, OSError) as e:
    # Fall back to stdout logging if file logging fails
    logger.warning(f"Could not enable file-based memory logging ({e}), using stdout")
    memory_logger.propagate = True  # Send to root logger instead


def main():
    """Main entry point"""
    logger.info("Starting DNSMon...")

    # Start FastAPI server - initialization happens in startup event
    uvicorn.run(
        "backend.api:app",
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )


if __name__ == "__main__":
    main()
