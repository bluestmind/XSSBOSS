"""Logging configuration."""
import logging
import sys
from backend_api.config import settings


def setup_logging():
    """Configure application logging."""
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific loggers
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # Attach diagnostic log bridge
    try:
        from backend_api.services.log_service import PythonLogHandlerBridge
        bridge_handler = PythonLogHandlerBridge()
        bridge_handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(bridge_handler)
    except Exception:
        pass
    
    return logging.getLogger(__name__)


logger = setup_logging()

