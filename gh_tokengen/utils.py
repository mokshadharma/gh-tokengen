import sys
import re
from pathlib import Path
from typing import NoReturn, List, Union

__version__ = "1.0.0"

# Constants
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_JWT_EXPIRY = 600
MAX_JWT_EXPIRY = 600
MIN_JWT_EXPIRY = 1
DEFAULT_USER_AGENT = f"GitHubAppAuth-Script/{__version__}"
class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def eprint(*args, **kwargs) -> None:
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def debug_print(message: str, debug: bool) -> None:
    """Print debug message to stderr if debug mode is enabled."""
    if debug:
        eprint(f"[DEBUG] {message}")


def fatal_error(message: str) -> NoReturn:
    """Print error message to stderr and exit with status 1."""
    eprint(f"Error: {message}")
    sys.exit(1)


def expand_path(path_str: str) -> Path:
    """Expand ~ and environment variables in path string."""
    return Path(path_str).expanduser().resolve()

def natural_sort_key(s: str) -> List[Union[int, str]]:
    """
    Generate a sort key for natural sorting (handles numbers in strings).

    Args:
        s: String to generate sort key for

    Returns:
        List of alternating strings and integers for proper sorting
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(r'(\d+)', s)]
