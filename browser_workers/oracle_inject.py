"""Oracle injection script loader."""
from pathlib import Path


def get_oracle_script() -> str:
    """Load Oracle injection script.
    
    Returns:
        JavaScript code as string
    """
    script_path = Path(__file__).parent / "oracle_inject.js"
    with open(script_path, 'r', encoding='utf-8') as f:
        return f.read()

