#!/usr/bin/env python3
"""
gh-tokengen - an UNOFFICIAL GitHub App Authentication Token Generator

Generates installation tokens for GitHub Apps by creating a JWT from a private key
and exchanging it with the GitHub API.

NOTE:  This program is NOT supported or endorsed by GitHub.  Use at own risk.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, NoReturn, Callable
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
import base64
import hashlib
import hmac
import re

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


def validate_pem_file(pem_path: Path, force: bool) -> None:
    """
    Validate that the PEM file exists and is readable.
    Existence and readability checks always run, even with --force.

    Args:
        pem_path: Path to the PEM file
        force: Skip format validation if True (but still check existence/readability)

    Raises:
        ValidationError: If validation fails
    """
    # Always check existence (even with --force)
    if not pem_path.exists():
        raise ValidationError(
            f"Cannot find the PEM file at '{pem_path}'.\n"
            f"Please check that the path is correct and the file exists."
        )

    if not pem_path.is_file():
        raise ValidationError(
            f"The path '{pem_path}' exists but is not a file.\n"
            f"Please provide the path to a PEM file, not a directory."
        )

    # Always check readability (even with --force)
    try:
        # Actually attempt to read the file to verify permissions
        content = pem_path.read_text()
    except PermissionError:
        raise ValidationError(
            f"Permission denied when trying to read '{pem_path}'.\n"
            f"Please check that you have read permissions for this file."
        )
    except Exception as e:
        raise ValidationError(
            f"Failed to read PEM file '{pem_path}': {e}\n"
            f"Please ensure the file is accessible and not corrupted."
        )

    # Basic format validation (can be skipped with --force)
    if not force:
        if "BEGIN" not in content or "PRIVATE KEY" not in content:
            raise ValidationError(
                f"The file '{pem_path}' does not appear to be a valid private key.\n"
                f"Expected to find 'BEGIN' and 'PRIVATE KEY' markers in the file.\n"
                f"Please provide a valid PEM-formatted private key file."
            )


def validate_client_id(client_id: str, force: bool) -> None:
    """
    Validate GitHub App Client ID format.

    Args:
        client_id: The Client ID to validate
        force: Skip validation if True

    Raises:
        ValidationError: If validation fails
    """
    if force:
        return

    if not client_id:
        raise ValidationError(
            "Client ID cannot be empty.\n"
            "Please enter your GitHub App Client ID (e.g., Iv1.1234567890abcdef)."
        )

    if not client_id.strip():
        raise ValidationError(
            "Client ID contains only whitespace.\n"
            "Please enter a valid GitHub App Client ID (e.g., Iv1.1234567890abcdef)."
        )

    if client_id != client_id.strip():
        raise ValidationError(
            f"Client ID contains leading or trailing whitespace: '{client_id}'\n"
            "Please remove any extra spaces."
        )

    if not client_id.replace('.', '').isalnum():
        raise ValidationError(
            f"Client ID contains invalid characters: '{client_id}'\n"
            "GitHub App Client IDs should contain only alphanumeric characters and dots.\n"
            "Example: Iv1.1234567890abcdef"
        )


def validate_installation_id(installation_id: str, force: bool) -> None:
    """
    Validate Installation ID is numeric.

    Args:
        installation_id: The Installation ID to validate
        force: Skip validation if True

    Raises:
        ValidationError: If validation fails
    """
    if force:
        return

    if not installation_id:
        raise ValidationError(
            "Installation ID cannot be empty.\n"
            "Please enter the numeric Installation ID for your GitHub App."
        )

    if not installation_id.strip():
        raise ValidationError(
            "Installation ID contains only whitespace.\n"
            "Please enter a valid numeric Installation ID (e.g., 12345678)."
        )

    if installation_id != installation_id.strip():
        raise ValidationError(
            f"Installation ID contains leading or trailing whitespace: '{installation_id}'\n"
            "Please remove any extra spaces."
        )

    if not installation_id.isdigit():
        raise ValidationError(
            f"Installation ID must be numeric: '{installation_id}'\n"
            "GitHub App Installation IDs contain only digits.\n"
            "Example: 12345678"
        )


def validate_jwt_expiry(expiry: int) -> None:
    """
    Validate JWT expiry is within allowed range.

    Args:
        expiry: JWT expiry time in seconds

    Raises:
        ValidationError: If expiry is out of range
    """
    if expiry < MIN_JWT_EXPIRY or expiry > MAX_JWT_EXPIRY:
        raise ValidationError(
            f"JWT expiry must be between {MIN_JWT_EXPIRY} and {MAX_JWT_EXPIRY} seconds"
        )


def validate_api_url(api_url: str) -> None:
    """
    Validate that the API URL has proper syntax and uses http:// or https://.

    Args:
        api_url: The API URL to validate

    Raises:
        ValidationError: If the URL is invalid or uses an unsupported scheme
    """
    if not api_url:
        raise ValidationError("API URL cannot be empty")

    try:
        parsed = urlparse(api_url)

        # Check if scheme is present and valid
        if not parsed.scheme:
            raise ValidationError(
                f"Invalid API URL: '{api_url}'\n"
                f"The URL must include a scheme (http:// or https://).\n"
                f"Example: https://api.github.com"
            )

        if parsed.scheme not in ('http', 'https'):
            raise ValidationError(
                f"Invalid API URL scheme: '{parsed.scheme}'\n"
                f"The URL must use either 'http://' or 'https://'.\n"
                f"Example: https://api.github.com"
            )

        # Check if netloc (domain) is present
        if not parsed.netloc:
            raise ValidationError(
                f"Invalid API URL: '{api_url}'\n"
                f"The URL must include a valid domain.\n"
                f"Example: https://api.github.com"
            )

    except ValueError as e:
        raise ValidationError(
            f"Invalid API URL format: '{api_url}'\n"
            f"Error: {e}\n"
            f"Example of valid URL: https://api.github.com"
        )


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def generate_jwt(
    client_id: str,
    pem_path: Path,
    expiry_seconds: int,
    debug: bool
) -> Tuple[str, int, int]:
    """
    Generate a JWT for GitHub App authentication.

    Args:
        client_id: GitHub App Client ID
        pem_path: Path to private key PEM file
        expiry_seconds: JWT expiry time in seconds
        debug: Enable debug output

    Returns:
        Tuple of (JWT string, issued_at timestamp, expires_at timestamp)
    """
    try:
        # Import cryptography library
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import jwt as pyjwt

        # Read private key
        with open(pem_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Generate JWT
        now = int(time.time())
        payload = {
            'iat': now - 60,  # Issued at (with 60s clock skew tolerance)
            'exp': now + expiry_seconds,  # Expiration
            'iss': client_id  # Issuer (Client ID)
        }

        token = pyjwt.encode(payload, private_key, algorithm='RS256')

        if debug:
            exp_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            debug_print(f"JWT generated successfully", debug)
            debug_print(f"JWT issued at: {datetime.fromtimestamp(payload['iat'], tz=timezone.utc)}", debug)
            debug_print(f"JWT expires at: {exp_time}", debug)
            debug_print(f"JWT preview: {token[:20]}...{token[-20:]}", debug)

        return token, payload['iat'], payload['exp']

    except ImportError:
        fatal_error(
            "Required dependencies not found. Install with:\n"
            "  pip install PyJWT cryptography"
        )
    except Exception as e:
        fatal_error(f"Failed to generate JWT: {e}")


def mask_token(token: str) -> str:
    """Mask a token for safe display, showing only first and last few characters."""
    if len(token) <= 10:
        return "***"
    return f"{token[:7]}...{token[-4:]}"


def format_headers_for_display(headers: Dict[str, str]) -> str:
    """Format HTTP headers for display, masking sensitive values."""
    lines = []
    for key, value in headers.items():
        if key.lower() == 'authorization':
            # Mask the token in Authorization header
            parts = value.split(' ')
            if len(parts) == 2:
                value = f"{parts[0]} {mask_token(parts[1])}"
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def make_api_request(
    url: str,
    token: str,
    user_agent: str,
    debug: bool,
    show_headers: bool
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Make an API request to GitHub.

    Args:
        url: API endpoint URL
        token: JWT token for authentication
        user_agent: User-Agent header value
        debug: Enable debug output
        show_headers: Show response headers

    Returns:
        Tuple of (response_data, response_headers)
    """
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'User-Agent': user_agent,
        'X-GitHub-Api-Version': '2022-11-28'
    }

    if debug:
        debug_print(f"Making API request to: {url}", debug)
        debug_print(f"Request headers:\n{format_headers_for_display(headers)}", debug)

    try:
        request = Request(url, headers=headers, method='POST')
        with urlopen(request) as response:
            response_headers = dict(response.headers)
            data = json.loads(response.read().decode('utf-8'))

            if show_headers or debug:
                eprint("\nResponse headers:")
                for key, value in response_headers.items():
                    eprint(f"  {key}: {value}")
                eprint()

            return data, response_headers

    except HTTPError as e:
        error_body = e.read().decode('utf-8')
        try:
            error_data = json.loads(error_body)
            error_msg = error_data.get('message', error_body)
        except:
            error_msg = error_body
        fatal_error(f"HTTP {e.code} error from GitHub API: {error_msg}")
    except URLError as e:
        fatal_error(f"Failed to connect to GitHub API: {e.reason}")
    except Exception as e:
        fatal_error(f"Unexpected error during API request: {e}")


def format_expiration(
    expires_at: str,
    format_type: str
) -> str:
    """
    Format expiration time according to specified format.

    Args:
        expires_at: ISO 8601 timestamp string
        format_type: Format type (human, iso8601, relative, unix)

    Returns:
        Formatted expiration string
    """
    try:
        exp_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))

        if format_type == 'iso8601':
            return exp_dt.isoformat()
        elif format_type == 'unix':
            return str(int(exp_dt.timestamp()))
        elif format_type == 'relative':
            now = datetime.now(timezone.utc)
            delta = exp_dt - now
            minutes = int(delta.total_seconds() / 60)
            return f"in {minutes} minutes"
        else:  # human (default)
            now = datetime.now(timezone.utc)
            delta = exp_dt - now
            minutes = int(delta.total_seconds() / 60)
            formatted_time = exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            return f"in {minutes} minutes ({formatted_time})"
    except Exception as e:
        debug_print(f"Failed to parse expiration time: {e}", True)
        return expires_at


def format_permissions(permissions: Dict[str, str]) -> str:
    """Format permissions dictionary for display."""
    if not permissions:
        return "  (none)"

    lines = []
    for resource, level in sorted(permissions.items()):
        lines.append(f"  {resource}: {level}")
    return "\n".join(lines)


def output_jwt(
    jwt_token: str,
    issued_at: int,
    expires_at: int,
    output_format: str,
    quiet: bool
) -> None:
    """
    Output the JWT in the specified format.

    Args:
        jwt_token: The JWT string
        issued_at: Unix timestamp when JWT was issued
        expires_at: Unix timestamp when JWT expires
        output_format: Output format (text, json, env, header)
        quiet: Suppress non-essential output
    """
    if output_format == 'json':
        output = {
            'jwt': jwt_token,
            'issued_at': datetime.fromtimestamp(issued_at, tz=timezone.utc).isoformat(),
            'expires_at': datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
        }
        print(json.dumps(output, indent=2))

    elif output_format == 'env':
        print(f"export GITHUB_TOKEN={jwt_token}")

    elif output_format == 'header':
        print(f"Authorization: Bearer {jwt_token}")

    else:  # text (default)
        print(jwt_token)


def output_token(
    token_data: Dict[str, Any],
    output_format: str,
    quiet: bool,
    timestamp_format: str
) -> None:
    """
    Output the installation token in the specified format.

    Args:
        token_data: Token response data from GitHub API
        output_format: Output format (text, json, env, header)
        quiet: Suppress non-essential output
        timestamp_format: How to format timestamps
    """
    token = token_data.get('token', '')

    if output_format == 'json':
        output = {
            'token': token,
            'expires_at': token_data.get('expires_at', ''),
            'permissions': token_data.get('permissions', {}),
            'repository_selection': token_data.get('repository_selection', '')
        }

        # Calculate expires_in_seconds
        try:
            exp_dt = datetime.fromisoformat(
                token_data.get('expires_at', '').replace('Z', '+00:00')
            )
            now = datetime.now(timezone.utc)
            expires_in = int((exp_dt - now).total_seconds())
            output['expires_in_seconds'] = expires_in
        except:
            pass

        print(json.dumps(output, indent=2))

    elif output_format == 'env':
        print(f"export GITHUB_TOKEN={token}")

    elif output_format == 'header':
        print(f"Authorization: Bearer {token}")

    else:  # text (default)
        print(token)


def get_installation_token(
    client_id: str,
    pem_path: Path,
    installation_id: str,
    api_url: str,
    jwt_expiry: int,
    user_agent: str,
    debug: bool,
    show_headers: bool,
    dry_run: bool
) -> Dict[str, Any]:
    """
    Get an installation token from GitHub API.

    Args:
        client_id: GitHub App Client ID
        pem_path: Path to private key PEM file
        installation_id: Installation ID
        api_url: GitHub API base URL
        jwt_expiry: JWT expiry time in seconds
        user_agent: User-Agent header value
        debug: Enable debug output
        show_headers: Show response headers
        dry_run: Don't actually make the API call

    Returns:
        Token data from GitHub API
    """
    # Generate JWT
    jwt_token, issued_at, expires_at = generate_jwt(client_id, pem_path, jwt_expiry, debug)

    # Prepare API request
    endpoint = f"{api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens"

    if dry_run:
        eprint("\n[DRY RUN] Would make the following API request:")
        eprint(f"  URL: {endpoint}")
        eprint(f"  Method: POST")
        eprint(f"  Headers:")
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github+json',
            'User-Agent': user_agent,
            'X-GitHub-Api-Version': '2022-11-28'
        }
        eprint(format_headers_for_display(headers))
        eprint("\n[DRY RUN] Exiting without making actual API call")
        sys.exit(0)

    # Exchange JWT for installation token
    token_data, response_headers = make_api_request(
        endpoint,
        jwt_token,
        user_agent,
        debug,
        show_headers
    )

    return token_data


def natural_sort_key(s: str) -> list:
    """
    Generate a sort key for natural sorting (handles numbers in strings).

    Args:
        s: String to generate sort key for

    Returns:
        List of alternating strings and integers for proper sorting
    """
    import re
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(r'(\d+)', s)]


class FuzzyPemCompleter:
    """
    Custom completer for PEM file selection with fuzzy matching.

    Supports directory navigation with fuzzy matching on each path component.
    Matches *.pem files and directories, with context-aware searching.

    Implements prompt_toolkit's Completer protocol via duck typing.
    """

    def __init__(self, base_dir: Path):
        """
        Initialize the fuzzy completer.

        Args:
            base_dir: Starting directory for path completion
        """
        self.base_dir = base_dir
        from rapidfuzz import fuzz, process
        self.fuzz = fuzz
        self.process = process

    def _expand_path(self, path_str: str) -> Path:
        """Expand ~ and $HOME in path string."""
        expanded = path_str.replace('$HOME', str(Path.home()))
        return Path(expanded).expanduser()

    def _get_candidates(self, directory: Path, is_final_segment: bool) -> list[Path]:
        """
        Get completion candidates from a directory.

        Args:
            directory: Directory to search in
            is_final_segment: If True, include *.pem files; if False, only directories

        Returns:
            List of Path objects for candidates
        """
        if not directory.exists() or not directory.is_dir():
            return []

        candidates = []
        try:
            for item in directory.iterdir():
                if item.is_dir():
                    candidates.append(item)
                elif is_final_segment and item.is_file() and item.suffix == '.pem':
                    candidates.append(item)
        except PermissionError:
            pass

        return candidates

    def _fuzzy_match(self, query: str, candidates: list[Path]) -> list[tuple[str, float, Path]]:
        """
        Perform fuzzy matching on candidates.

        Args:
            query: Search query string
            candidates: List of Path objects to match against

        Returns:
            List of tuples (name, score, path) sorted by score then natural sort
        """
        if not query:
            # No query - return all candidates sorted naturally
            results = [(c.name, 100.0, c) for c in candidates]
        else:
            # Check if query characters appear in order in the candidate name (case-insensitive)
            def has_ordered_chars(query_str: str, target_str: str) -> bool:
                """Check if all characters in query appear in order in target."""
                query_lower = query_str.lower()
                target_lower = target_str.lower()
                query_idx = 0
                for char in target_lower:
                    if query_idx < len(query_lower) and char == query_lower[query_idx]:
                        query_idx += 1
                return query_idx == len(query_lower)

            # Filter candidates to only those with characters in order
            valid_candidates = [c for c in candidates if has_ordered_chars(query, c.name)]

            if not valid_candidates:
                return []

            # Fuzzy match against basenames using QRatio for better sequential matching
            names = [c.name for c in valid_candidates]
            matches = self.process.extract(
                query,
                names,
                scorer=self.fuzz.QRatio,
                limit=None
                # No score_cutoff - we already filtered by ordered characters
            )

            # Create lookup dict
            name_to_path = {c.name: c for c in valid_candidates}
            results = [(name, score, name_to_path[name]) for name, score, _ in matches]

        # Sort by score (descending) then natural sort
        results.sort(key=lambda x: (-x[1], natural_sort_key(x[0])))
        return results

    def get_completions(self, document, complete_event):
        """
        Generate completions for the current document state.

        Args:
            document: The prompt_toolkit Document object
            complete_event: The completion event

        Yields:
            Completion objects for matching candidates
        """
        from prompt_toolkit.completion import Completion

        text = document.text_before_cursor

        # Parse the path into components
        if '/' in text:
            # Split into directory parts and final query
            parts = text.split('/')
            final_query = parts[-1]
            dir_parts = parts[:-1]

            # Build the directory path
            if text.startswith('/'):
                current_dir = Path('/')
            elif text.startswith('~/') or text.startswith('$HOME/'):
                current_dir = Path.home()
            else:
                current_dir = self.base_dir

            # Navigate through directory parts (but not the final query part)
            for i, part in enumerate(dir_parts):
                # Skip empty parts and special markers at the start
                if not part:
                    continue
                if i == 0 and part in ('~', '$HOME'):
                    # Already handled above by setting current_dir to home
                    continue

                # This part is an intermediate directory to navigate through
                # Get subdirectories and fuzzy match
                subdirs = [p for p in self._get_candidates(current_dir, False)]
                if not subdirs:
                    return

                matches = self._fuzzy_match(part, subdirs)
                if matches:
                    # Use best match
                    current_dir = matches[0][2]
                else:
                    return

            # Get candidates for final segment (includes .pem files)
            # This is where we search for the final_query
            candidates = self._get_candidates(current_dir, True)
            matches = self._fuzzy_match(final_query, candidates)

            # Generate completions
            for name, score, path in matches:
                if path.is_dir():
                    completion_text = name + '/'
                else:
                    completion_text = name

                # Calculate how much of the final query to replace
                yield Completion(
                    completion_text,
                    start_position=-len(final_query),
                    display=completion_text
                )
        else:
            # No slash - match in base directory
            candidates = self._get_candidates(self.base_dir, True)
            matches = self._fuzzy_match(text, candidates)

            for name, score, path in matches:
                if path.is_dir():
                    completion_text = name + '/'
                else:
                    completion_text = name

                yield Completion(
                    completion_text,
                    start_position=-len(text),
                    display=completion_text
                )

    async def get_completions_async(self, document, complete_event):
        """
        Async version of get_completions required by prompt_toolkit.

        Args:
            document: The prompt_toolkit Document object
            complete_event: The completion event

        Yields:
            Completion objects for matching candidates
        """
        # Delegate to synchronous version since our operations are fast
        for completion in self.get_completions(document, complete_event):
            yield completion


def detect_editing_mode_from_inputrc() -> str:
    """
    Detect editing mode (vi or emacs) from ~/.inputrc.

    Returns:
        'vi' or 'emacs' (defaults to 'emacs' if not specified or file doesn't exist)
    """
    inputrc_path = Path.home() / '.inputrc'

    if not inputrc_path.exists():
        return 'emacs'

    try:
        content = inputrc_path.read_text()
        # Look for "set editing-mode vi" or "set editing-mode emacs"
        # Handle various whitespace and comment scenarios
        for line in content.splitlines():
            # Strip comments (everything after #)
            line = line.split('#')[0].strip()

            # Match "set editing-mode vi" or "set editing-mode emacs"
            match = re.match(r'^set\s+editing-mode\s+(vi|emacs)\s*$', line, re.IGNORECASE)
            if match:
                return match.group(1).lower()
    except Exception:
        # If we can't read or parse the file, default to emacs
        pass

    return 'emacs'


def prompt_for_input(
    prompt_text: str,
    enable_path_completion: bool = False,
    validator_func: Optional[Callable[[str], None]] = None
) -> str:
    """
    Prompt user for input on stderr with rich line editing.

    Args:
        prompt_text: The prompt to display
        enable_path_completion: Enable file path autocompletion with fuzzy matching
        validator_func: Optional validation function for non-path inputs

    Returns:
        User input string
    """
    try:
        from prompt_toolkit import prompt, PromptSession
        from prompt_toolkit.completion import PathCompleter, Completer, Completion
        from prompt_toolkit.enums import EditingMode
        from prompt_toolkit.output import create_output
        from prompt_toolkit.validation import Validator, ValidationError as PTValidationError
        from prompt_toolkit.formatted_text import HTML, ANSI
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.keys import Keys
        from prompt_toolkit.layout.processors import Processor, Transformation
        from prompt_toolkit.document import Document
        import os
        import threading
        import time

        # Detect editing mode from ~/.inputrc
        mode_str = detect_editing_mode_from_inputrc()
        editing_mode = EditingMode.VI if mode_str == 'vi' else EditingMode.EMACS

        # Configure completer based on path completion setting
        if enable_path_completion:
            # Use fuzzy PEM completer with current working directory
            base_dir = Path(os.getcwd())
            completer = FuzzyPemCompleter(base_dir)
        else:
            completer = None

        # Create output to stderr
        output = create_output(stdout=sys.stderr)

        # Shared state for error display
        class ValidationState:
            def __init__(self):
                self.error_message: str = ""
                self.flash_error: bool = False
                self.flash_thread: Optional[threading.Thread] = None

        state = ValidationState()

        # Bottom toolbar for error messages
        def bottom_toolbar():
            if state.flash_error:
                # Flashing: black text on red background
                return HTML('<style bg="ansired" fg="ansiblack">  {}  </style>').format(state.error_message)
            elif state.error_message:
                # Normal: red text on black background
                return HTML('<style fg="ansired">  {}  </style>').format(state.error_message)
            return ""

        # Validator for inputs
        class InputValidator(Validator):
            def validate(self, document):
                text = document.text.strip()

                if enable_path_completion:
                    # Path validation with fuzzy matching
                    if not text:
                        state.error_message = ""
                        return

                    # Expand path for validation
                    try:
                        expanded = text.replace('$HOME', str(Path.home()))
                        path = Path(expanded).expanduser()

                        # Determine base directory
                        if text.startswith('/'):
                            base_dir = Path('/')
                        elif text.startswith('~/') or text.startswith('$HOME/'):
                            base_dir = Path.home()
                        else:
                            base_dir = Path(os.getcwd())

                        # Parse path into components
                        if '/' in text:
                            parts = text.split('/')
                            final_query = parts[-1]
                            dir_parts = parts[:-1]

                            # Build directory path
                            current_dir = base_dir

                            # Navigate through directory parts
                            for i, part in enumerate(dir_parts):
                                if not part:
                                    if i == 0 and text.startswith('/'):
                                        current_dir = Path('/')
                                    continue

                                if i == 0 and part in ('~', '$HOME'):
                                    current_dir = Path.home()
                                    continue

                                # Get subdirectories
                                if not current_dir.exists():
                                    if final_query:
                                        state.error_message = "no match"
                                        raise PTValidationError(message="no match")
                                    return

                                subdirs = [p for p in current_dir.iterdir() if p.is_dir()] if current_dir.exists() else []

                                # Try exact match first
                                matched = None
                                for subdir in subdirs:
                                    if subdir.name == part:
                                        matched = subdir
                                        break

                                # If no exact match, try fuzzy match using ordered characters
                                if not matched:
                                    def has_ordered_chars(query_str: str, target_str: str) -> bool:
                                        query_lower = query_str.lower()
                                        target_lower = target_str.lower()
                                        query_idx = 0
                                        for char in target_lower:
                                            if query_idx < len(query_lower) and char == query_lower[query_idx]:
                                                query_idx += 1
                                        return query_idx == len(query_lower)

                                    # Find subdirs that match
                                    fuzzy_matches = [s for s in subdirs if has_ordered_chars(part, s.name)]
                                    if fuzzy_matches:
                                        # Use the first fuzzy match (could score and sort, but keep it simple)
                                        matched = fuzzy_matches[0]

                                if matched:
                                    current_dir = matched
                                else:
                                    # No match at all - this is an error if final_query exists
                                    if final_query:
                                        state.error_message = "no match"
                                        raise PTValidationError(message="no match")
                                    return

                            # Check final segment if present
                            if final_query:
                                # Get candidates in current directory
                                if not current_dir.exists():
                                    state.error_message = "no match"
                                    raise PTValidationError(message="no match")

                                candidates = []
                                try:
                                    for item in current_dir.iterdir():
                                        if item.is_dir() or (item.is_file() and item.suffix == '.pem'):
                                            candidates.append(item)
                                except PermissionError:
                                    state.error_message = "no match"
                                    raise PTValidationError(message="no match")

                                if not candidates:
                                    state.error_message = "no match"
                                    raise PTValidationError(message="no match")

                                # Check if query characters appear in order in any candidate
                                def has_ordered_chars(query_str: str, target_str: str) -> bool:
                                    query_lower = query_str.lower()
                                    target_lower = target_str.lower()
                                    query_idx = 0
                                    for char in target_lower:
                                        if query_idx < len(query_lower) and char == query_lower[query_idx]:
                                            query_idx += 1
                                    return query_idx == len(query_lower)

                                has_match = any(has_ordered_chars(final_query, c.name) for c in candidates)

                                if not has_match:
                                    state.error_message = "no match"
                                    raise PTValidationError(message="no match")
                        else:
                            # No slash - check in base directory
                            # Special case: ~ or $HOME are always valid (they're directories)
                            if text in ('~', '$HOME'):
                                state.error_message = ""
                                return

                            if not base_dir.exists():
                                state.error_message = "no match"
                                raise PTValidationError(message="no match")

                            candidates = []
                            try:
                                for item in base_dir.iterdir():
                                    if item.is_dir() or (item.is_file() and item.suffix == '.pem'):
                                        candidates.append(item)
                            except PermissionError:
                                state.error_message = "no match"
                                raise PTValidationError(message="no match")

                            if not candidates:
                                state.error_message = "no match"
                                raise PTValidationError(message="no match")

                            # Check if query characters appear in order in any candidate
                            def has_ordered_chars(query_str: str, target_str: str) -> bool:
                                query_lower = query_str.lower()
                                target_lower = target_str.lower()
                                query_idx = 0
                                for char in target_lower:
                                    if query_idx < len(query_lower) and char == query_lower[query_idx]:
                                        query_idx += 1
                                return query_idx == len(query_lower)

                            has_match = any(has_ordered_chars(text, c.name) for c in candidates)

                            if not has_match:
                                state.error_message = "no match"
                                raise PTValidationError(message="no match")

                        # Valid input
                        state.error_message = ""

                    except PTValidationError:
                        raise
                    except Exception as e:
                        # Unexpected error - allow typing to continue
                        pass
                else:
                    # Non-path validation (only on Enter, handled in key binding)
                    pass

        validator = InputValidator()

        # Custom key bindings
        kb = KeyBindings()

        @kb.add(Keys.Backspace)
        def handle_backspace(event):
            """Handle backspace - keep completions visible."""
            buf = event.app.current_buffer
            if buf.cursor_position > 0:
                buf.delete_before_cursor(count=1)
                # Trigger completions if path completion is enabled
                if enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(Keys.ControlW)
        def handle_ctrl_w(event):
            """Handle Ctrl-W (delete word) - keep completions visible."""
            buf = event.app.current_buffer
            # Delete word before cursor (standard behavior)
            if buf.text:
                pos = buf.cursor_position
                # Find start of word
                text_before = buf.text[:pos]
                # Skip trailing whitespace
                while text_before and text_before[-1] in ' \t':
                    text_before = text_before[:-1]
                # Delete word characters
                while text_before and text_before[-1] not in ' \t/':
                    text_before = text_before[:-1]

                new_pos = len(text_before)
                buf.cursor_position = new_pos
                buf.text = text_before + buf.text[pos:]

                # Trigger completions if path completion is enabled
                if enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        def resolve_fuzzy_path(text: str) -> Optional[tuple[str, str]]:
            """Resolve a fuzzy path to an actual full path.

            Returns:
                Tuple of (unexpanded_path, expanded_path) or None if no match
            """
            if not text or not enable_path_completion:
                return None

            try:
                # Helper for ordered char matching
                def has_ordered_chars(query_str: str, target_str: str) -> bool:
                    query_lower = query_str.lower()
                    target_lower = target_str.lower()
                    query_idx = 0
                    for char in target_lower:
                        if query_idx < len(query_lower) and char == query_lower[query_idx]:
                            query_idx += 1
                    return query_idx == len(query_lower)

                # Track if path started with ~ or $HOME for preserving it
                starts_with_tilde = text.startswith('~/')
                starts_with_home = text.startswith('$HOME/')

                # Parse the path
                if '/' in text:
                    parts = text.split('/')

                    # Determine base directory
                    if text.startswith('/'):
                        current_dir = Path('/')
                        start_idx = 1
                        unexpanded_parts = ['']
                    elif starts_with_tilde or starts_with_home:
                        current_dir = Path.home()
                        start_idx = 1
                        unexpanded_parts = ['~' if starts_with_tilde else '$HOME']
                    else:
                        current_dir = Path(os.getcwd())
                        start_idx = 0
                        unexpanded_parts = []

                    # Navigate through each part
                    for i in range(start_idx, len(parts)):
                        part = parts[i]
                        if not part or part in ('~', '$HOME'):
                            continue

                        # Get candidates in current directory
                        is_last = (i == len(parts) - 1)
                        candidates = []

                        if current_dir.exists():
                            for item in current_dir.iterdir():
                                if is_last:
                                    # Last segment: include .pem files and directories
                                    if item.is_dir() or (item.is_file() and item.suffix == '.pem'):
                                        candidates.append(item)
                                else:
                                    # Intermediate: only directories
                                    if item.is_dir():
                                        candidates.append(item)

                        # Try exact match first
                        matched = None
                        for candidate in candidates:
                            if candidate.name == part:
                                matched = candidate
                                break

                        # If no exact match, try fuzzy matching
                        if not matched:
                            fuzzy_matches = [c for c in candidates if has_ordered_chars(part, c.name)]
                            if fuzzy_matches:
                                # Use the best match (first one after sorting by score)
                                from rapidfuzz import fuzz, process
                                names = [c.name for c in fuzzy_matches]
                                matches = process.extract(part, names, scorer=fuzz.QRatio, limit=1)
                                if matches:
                                    best_name = matches[0][0]
                                    matched = next(c for c in fuzzy_matches if c.name == best_name)

                        if matched:
                            current_dir = matched
                            unexpanded_parts.append(matched.name)
                        else:
                            return None

                    # Return both unexpanded and expanded paths
                    unexpanded = '/'.join(unexpanded_parts)
                    return (unexpanded, str(current_dir))
                else:
                    # No slash - match in current directory
                    base_dir = Path(os.getcwd())
                    candidates = []

                    if base_dir.exists():
                        for item in base_dir.iterdir():
                            if item.is_dir() or (item.is_file() and item.suffix == '.pem'):
                                candidates.append(item)

                    # Try exact match first
                    for candidate in candidates:
                        if candidate.name == text:
                            return (text, str(candidate))

                    # Try fuzzy match
                    fuzzy_matches = [c for c in candidates if has_ordered_chars(text, c.name)]
                    if fuzzy_matches:
                        from rapidfuzz import fuzz, process
                        names = [c.name for c in fuzzy_matches]
                        matches = process.extract(text, names, scorer=fuzz.QRatio, limit=1)
                        if matches:
                            best_name = matches[0][0]
                            matched = next(c for c in fuzzy_matches if c.name == best_name)
                            return (matched.name, str(matched))

                    return None
            except Exception:
                return None

        @kb.add(Keys.ControlM)  # Enter key
        def handle_enter(event):
            """Handle Enter key - validate before accepting."""
            buf = event.app.current_buffer
            text = buf.text.strip()

            if enable_path_completion:
                # For path input, resolve fuzzy path to actual path
                if not text:
                    return

                # Try to resolve the fuzzy path
                result = resolve_fuzzy_path(text)
                if result:
                    unexpanded_path, expanded_path = result
                    # Use unexpanded path for display, expanded for validation
                    buf.text = unexpanded_path
                    buf.cursor_position = len(unexpanded_path)
                    text = unexpanded_path
                    validation_path = expanded_path
                else:
                    validation_path = text

                try:
                    path = Path(validation_path)

                    # Resolve relative to current directory if needed
                    if not path.is_absolute():
                        path = Path(os.getcwd()) / path

                    # Check if it exists
                    if not path.exists():
                        state.error_message = "not a valid *.pem file name"
                        return

                    # Check if it's a directory
                    if path.is_dir():
                        state.error_message = "not a valid *.pem file name"
                        return

                    # Must be a .pem file
                    if path.suffix != '.pem':
                        state.error_message = "not a valid *.pem file name"
                        return

                except Exception:
                    state.error_message = "not a valid *.pem file name"
                    return
            else:
                # For non-path inputs, validate using custom validator
                if validator_func:
                    try:
                        validator_func(text)
                        state.error_message = ""
                    except ValidationError as e:
                        state.error_message = str(e).split('\n')[0]  # First line only
                        return

            # Accept the input
            buf.validate_and_handle()

        @kb.add(Keys.ControlI)  # Tab key
        def handle_tab(event):
            """Handle Tab key - show completions or flash error."""
            buf = event.app.current_buffer

            if enable_path_completion and state.error_message and not buf.complete_state:
                # Flash the error
                state.flash_error = True

                def unflash():
                    time.sleep(0.5)
                    state.flash_error = False
                    event.app.invalidate()

                if state.flash_thread is None or not state.flash_thread.is_alive():
                    state.flash_thread = threading.Thread(target=unflash, daemon=True)
                    state.flash_thread.start()
            else:
                # Normal tab completion
                buf.complete_next()

        # Create a session with the desired settings
        session = PromptSession(
            message=prompt_text,
            editing_mode=editing_mode,
            completer=completer,  # type: ignore - FuzzyPemCompleter implements Completer protocol
            complete_while_typing=enable_path_completion,
            output=output,
            enable_history_search=False,
            validator=validator if enable_path_completion else None,
            validate_while_typing=enable_path_completion,
            key_bindings=kb,
            bottom_toolbar=bottom_toolbar if enable_path_completion or validator_func else None,
            reserve_space_for_menu=8  # Reserve space for completion menu
        )

        # Add auto-expansion handler for path completion
        if enable_path_completion:
            def on_text_changed(_):
                """Auto-expand ~ and single directory matches."""
                buf = session.default_buffer
                text = buf.text

                # Don't auto-expand if completing
                if buf.complete_state:
                    return

                # Case 1: Just typed ~ or $HOME (auto-append /)
                if text in ('~', '$HOME'):
                    buf.insert_text('/')
                    return

                # Case 2: Check if there's exactly one match and it's a directory
                if text and not text.endswith('/') and '/' not in text[:-1]:
                    try:
                        completions = list(completer.get_completions(buf.document, None))

                        # If exactly one completion and it's a directory, auto-expand it
                        if len(completions) == 1:
                            completion = completions[0]
                            if completion.text.endswith('/'):
                                # Replace buffer text with the completion
                                buf.text = completion.text
                                buf.cursor_position = len(completion.text)
                    except Exception:
                        pass

            session.default_buffer.on_text_changed += on_text_changed

        result = session.prompt()
        return result.strip()

    except ImportError as e:
        # Fallback to basic input if prompt_toolkit is not available
        eprint(f"Warning: Advanced input features unavailable ({e})")
        eprint(prompt_text, end='')
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            eprint()
            fatal_error("Input cancelled by user")
    except (EOFError, KeyboardInterrupt):
        eprint()
        fatal_error("Input cancelled by user")


def validate_and_collect_errors(
    client_id: str,
    pem_path: Path,
    installation_id: Optional[str],
    force: bool,
    jwt_only: bool
) -> list[str]:
    """
    Validate all inputs and collect any errors.

    Args:
        client_id: GitHub App Client ID
        pem_path: Path to private key PEM file
        installation_id: Installation ID (can be None in JWT-only mode)
        force: Skip validation where allowed
        jwt_only: Whether running in JWT-only mode

    Returns:
        List of error messages (empty if all validations pass)
    """
    errors = []

    # Validate client ID
    try:
        validate_client_id(client_id, force)
    except ValidationError as e:
        errors.append(f"Client ID: {e}")

    # Validate PEM file
    try:
        validate_pem_file(pem_path, force)
    except ValidationError as e:
        errors.append(f"PEM file: {e}")

    # Validate installation ID (only if not in JWT-only mode)
    if not jwt_only and installation_id:
        try:
            validate_installation_id(installation_id, force)
        except ValidationError as e:
            errors.append(f"Installation ID: {e}")

    return errors


def parse_arguments() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate installation tokens for GitHub Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (prompts for all inputs)
  %(prog)s

  # Provide all arguments
  %(prog)s --client-id Iv1.abc123 --pem-path ~/.ssh/app.pem --installation-id 12345678

  # Generate only JWT (no installation token)
  %(prog)s --jwt --client-id Iv1.abc123 --pem-path app.pem

  # Generate JWT in JSON format
  %(prog)s --jwt --client-id Iv1.abc123 --pem-path app.pem --output-format json

  # Output as environment variable
  %(prog)s --client-id Iv1.abc123 --pem-path app.pem --installation-id 12345678 --output-format env

  # Debug mode with headers
  %(prog)s --debug --headers --client-id Iv1.abc123 --pem-path app.pem --installation-id 12345678

  # Quiet mode (token only)
  %(prog)s --quiet --client-id Iv1.abc123 --pem-path app.pem --installation-id 12345678

  # Dry run to test configuration
  %(prog)s --dry-run --client-id Iv1.abc123 --pem-path app.pem --installation-id 12345678

  # GitHub Enterprise with custom API URL
  %(prog)s --api-url https://github.company.com/api/v3 --client-id Iv1.abc123 --pem-path app.pem --installation-id 12345678
        """
    )

    # Input arguments
    parser.add_argument(
        '--client-id',
        help='GitHub App Client ID (e.g., Iv1.1234567890abcdef)'
    )
    parser.add_argument(
        '--pem-path',
        help='Path to private key PEM file'
    )
    parser.add_argument(
        '--installation-id',
        help='GitHub App Installation ID'
    )

    # Configuration arguments
    parser.add_argument(
        '--api-url',
        default=DEFAULT_API_URL,
        help=f'GitHub API base URL (default: {DEFAULT_API_URL})'
    )
    parser.add_argument(
        '--jwt-expiry',
        type=int,
        default=DEFAULT_JWT_EXPIRY,
        help=f'JWT expiry time in seconds, 1-{MAX_JWT_EXPIRY} (default: {DEFAULT_JWT_EXPIRY})'
    )
    parser.add_argument(
        '--user-agent',
        default=DEFAULT_USER_AGENT,
        help=f'Custom User-Agent header (default: {DEFAULT_USER_AGENT})'
    )

    # Output arguments
    parser.add_argument(
        '--output-format',
        choices=['text', 'json', 'env', 'header'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--timestamp-format',
        choices=['human', 'iso8601', 'relative', 'unix'],
        default='human',
        help='Timestamp format (default: human)'
    )

    # Mode arguments
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output (verbose mode)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Quiet mode - only output the token'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate inputs and show what would be done without making API calls'
    )
    parser.add_argument(
        '--headers',
        action='store_true',
        help='Show response headers'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Skip input validation'
    )
    parser.add_argument(
        '--jwt',
        action='store_true',
        help='Generate and output only the JWT (do not exchange for installation token)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    args = parser.parse_args()

    # Validate mutually exclusive options
    if args.quiet and args.debug:
        parser.error("--quiet and --debug are mutually exclusive")

    if args.jwt and args.installation_id:
        parser.error("--jwt and --installation-id are mutually exclusive")

    return args


def main() -> None:
    """Main entry point."""
    args = parse_arguments()

    # Validate arguments before doing anything else
    try:
        validate_jwt_expiry(args.jwt_expiry)
        validate_api_url(args.api_url)
    except ValidationError as e:
        fatal_error(str(e))

    # Determine if we're in interactive mode (prompting for inputs)
    interactive_mode = not args.client_id or not args.pem_path or (not args.jwt and not args.installation_id)

    # Get or prompt for required inputs
    client_id = args.client_id
    pem_path_str = args.pem_path
    installation_id = args.installation_id
    pem_path = None

    if interactive_mode:
        # Interactive mode: validate each input immediately after entry
        if not client_id:
            client_id = prompt_for_input(
                "Enter GitHub App Client ID: ",
                enable_path_completion=False,
                validator_func=lambda text: validate_client_id(text, args.force)
            )

        if not pem_path_str:
            pem_path_str = prompt_for_input(
                "Enter path to private key PEM file: ",
                enable_path_completion=True
            )

        # Expand and validate PEM path immediately (but keep original for display)
        try:
            pem_path = expand_path(pem_path_str)
        except Exception as e:
            fatal_error(f"Invalid file path: {e}")

        try:
            validate_pem_file(pem_path, args.force)
        except ValidationError as e:
            fatal_error(str(e))

        # Installation ID is only needed when not in JWT-only mode
        if not args.jwt and not installation_id:
            installation_id = prompt_for_input(
                "Enter Installation ID: ",
                enable_path_completion=False,
                validator_func=lambda text: validate_installation_id(text, args.force)
            )
    else:
        # Command-line mode: collect all validation errors and report together
        # Expand path first
        try:
            pem_path = expand_path(pem_path_str)
        except Exception as e:
            fatal_error(f"Invalid file path '{pem_path_str}': {e}")

        # Validate all inputs and collect errors
        validation_errors = validate_and_collect_errors(
            client_id=client_id,
            pem_path=pem_path,
            installation_id=installation_id,
            force=args.force,
            jwt_only=args.jwt
        )

        # If there are validation errors, report them all at once
        if validation_errors:
            eprint("Validation failed with the following error(s):\n")
            for i, error in enumerate(validation_errors, 1):
                # Add proper indentation for multi-line error messages
                indented_error = error.replace('\n', '\n  ')
                eprint(f"{i}. {indented_error}")
                if i < len(validation_errors):
                    eprint()  # Blank line between errors
            sys.exit(1)

    # Show progress unless in quiet mode (use unexpanded path for display)
    if not args.quiet:
        eprint(f"Reading private key from: {pem_path_str}")

    debug_print(f"Client ID: {client_id}", args.debug)
    if not args.jwt:
        debug_print(f"Installation ID: {installation_id}", args.debug)
    debug_print(f"PEM path: {pem_path_str}", args.debug)
    debug_print(f"API URL: {args.api_url}", args.debug)
    debug_print(f"User-Agent: {args.user_agent}", args.debug)

    # If JWT-only mode, generate and output JWT then exit
    if args.jwt:
        jwt_token, issued_at, expires_at = generate_jwt(
            client_id=client_id,
            pem_path=pem_path,
            expiry_seconds=args.jwt_expiry,
            debug=args.debug
        )

        if args.debug:
            debug_print("Successfully generated JWT!", args.debug)
            debug_print(f"JWT: {mask_token(jwt_token)}", args.debug)
            eprint()  # Blank line before output
        elif not args.quiet:
            eprint(f"Generating JWT (expires in {args.jwt_expiry} seconds)...")
            eprint("Successfully generated JWT!\n")

        output_jwt(jwt_token, issued_at, expires_at, args.output_format, args.quiet)
        return

    # Get installation token
    if not args.quiet and not args.debug:
        eprint(f"Generating JWT (expires in {args.jwt_expiry} seconds)...")
        eprint("Exchanging JWT for installation token...")

    token_data = get_installation_token(
        client_id=client_id,
        pem_path=pem_path,
        installation_id=installation_id,
        api_url=args.api_url,
        jwt_expiry=args.jwt_expiry,
        user_agent=args.user_agent,
        debug=args.debug,
        show_headers=args.headers,
        dry_run=args.dry_run
    )

    # Show success message and permissions in debug mode
    if args.debug:
        debug_print("Successfully obtained installation token!", args.debug)
        debug_print(f"Token: {mask_token(token_data.get('token', ''))}", args.debug)

        expires_at = token_data.get('expires_at', '')
        if expires_at:
            debug_print(f"Expires at: {expires_at}", args.debug)

        permissions = token_data.get('permissions', {})
        if permissions:
            eprint("\n[DEBUG] Permissions granted:")
            eprint(format_permissions(permissions))

        repo_selection = token_data.get('repository_selection', '')
        if repo_selection:
            debug_print(f"Repository selection: {repo_selection}", args.debug)

        eprint()  # Blank line before output
    elif not args.quiet:
        eprint("Successfully obtained installation token!\n")

    # Output token
    if args.quiet:
        output_token(token_data, args.output_format, True, args.timestamp_format)
    else:
        if args.output_format == 'text':
            # For text format, show token and expiration in non-quiet mode
            print(f"Token: {token_data.get('token', '')}\n")
            expires_at = token_data.get('expires_at', '')
            if expires_at:
                formatted_exp = format_expiration(expires_at, args.timestamp_format)
                print(f"Expires: {formatted_exp}")
        else:
            output_token(token_data, args.output_format, False, args.timestamp_format)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        eprint("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        fatal_error(f"Unexpected error: {e}")
