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
from typing import Dict, Any, Optional, Tuple, NoReturn, Callable, List, Union, Iterator
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
import base64
import re
import threading

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
        from typing import cast

        # Read private key
        with open(pem_path, 'rb') as key_file:
            # Cast to RSAPrivateKey to satisfy PyJWT's type hints.
            # load_pem_private_key() returns a PrivateKeyTypes union that includes key types
            # PyJWT doesn't accept (like DHPrivateKey), but GitHub Apps always use RSA keys.
            # See: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps
            # This cast tells the type checker we're confident this is an RSA key.
            private_key = cast(
                rsa.RSAPrivateKey,
                serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            )

        # Generate JWT
        now: int = int(time.time())
        payload: Dict[str, Union[int, str]] = {
            'iat': now - 60,  # Issued at (with 60s clock skew tolerance)
            'exp': now + expiry_seconds,  # Expiration
            'iss': client_id  # Issuer (Client ID)
        }

        token: str = pyjwt.encode(payload, private_key, algorithm='RS256')

        if debug:
            exp_time: datetime = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)  # type: ignore[arg-type]
            debug_print("JWT generated successfully", debug)
            debug_print(f"JWT issued at: {datetime.fromtimestamp(payload['iat'], tz=timezone.utc)}", debug)  # type: ignore[arg-type]
            debug_print(f"JWT expires at: {exp_time}", debug)
            debug_print(f"JWT preview: {token[:20]}...{token[-20:]}", debug)

        return token, int(payload['iat']), int(payload['exp'])  # type: ignore[arg-type]

    except ImportError as e:
        if debug:
            eprint(f"ImportError: {e}")
        fatal_error(
            "Required dependencies not found. Install with:\n"
            "  pip install PyJWT cryptography"
        )
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
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
    headers: Dict[str, str] = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'User-Agent': user_agent,
        'X-GitHub-Api-Version': '2022-11-28'
    }

    if debug:
        debug_print(f"Making API request to: {url}", debug)
        debug_print(f"Request headers:\n{format_headers_for_display(headers)}", debug)

    try:
        request: Request = Request(url, headers=headers, method='POST')
        with urlopen(request) as response:
            response_headers: Dict[str, str] = dict(response.headers)
            data: Dict[str, Any] = json.loads(response.read().decode('utf-8'))

            if show_headers or debug:
                eprint("\nResponse headers:")
                for key, value in response_headers.items():
                    eprint(f"  {key}: {value}")
                eprint()

            return data, response_headers

    except HTTPError as e:
        error_body = e.read().decode('utf-8')
        if debug:
            eprint(f"DEBUG: HTTP Error body: {error_body}")
            import traceback
            traceback.print_exc()
        try:
            error_data = json.loads(error_body)
            error_msg = error_data.get('message', error_body)
        except (json.JSONDecodeError, ValueError):
            error_msg = error_body
        fatal_error(f"HTTP {e.code} error from GitHub API: {error_msg}")
    except URLError as e:
        if debug:
            import traceback
            traceback.print_exc()
        fatal_error(f"Failed to connect to GitHub API: {e.reason}")
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
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
        exp_dt: datetime = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))

        if format_type == 'iso8601':
            return exp_dt.isoformat()
        elif format_type == 'unix':
            return str(int(exp_dt.timestamp()))
        elif format_type == 'relative':
            now_utc: datetime = datetime.now(timezone.utc)
            delta: timedelta = exp_dt - now_utc
            minutes: int = int(delta.total_seconds() / 60)
            return f"in {minutes} minutes"
        else:  # human (default)
            now_utc = datetime.now(timezone.utc)
            delta_time: timedelta = exp_dt - now_utc
            minutes_left: int = int(delta_time.total_seconds() / 60)
            formatted_time: str = exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            return f"in {minutes_left} minutes ({formatted_time})"
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
        output: Dict[str, str] = {
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
    token: str = token_data.get('token', '')

    if output_format == 'json':
        output: Dict[str, Any] = {
            'token': token,
            'expires_at': token_data.get('expires_at', ''),
            'permissions': token_data.get('permissions', {}),
            'repository_selection': token_data.get('repository_selection', '')
        }

        # Calculate expires_in_seconds
        try:
            exp_dt: datetime = datetime.fromisoformat(
                token_data.get('expires_at', '').replace('Z', '+00:00')
            )
            now: datetime = datetime.now(timezone.utc)
            expires_in: int = int((exp_dt - now).total_seconds())
            output['expires_in_seconds'] = expires_in
        except (ValueError, AttributeError, TypeError):
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
    jwt_token: str
    issued_at: int
    expires_at: int
    jwt_token, issued_at, expires_at = generate_jwt(client_id, pem_path, jwt_expiry, debug)

    # Prepare API request
    endpoint: str = f"{api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens"

    if dry_run:
        eprint("\n[DRY RUN] Would make the following API request:")
        eprint(f"  URL: {endpoint}")
        eprint("  Method: POST")
        eprint("  Headers:")
        headers: Dict[str, str] = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github+json',
            'User-Agent': user_agent,
            'X-GitHub-Api-Version': '2022-11-28'
        }
        eprint(format_headers_for_display(headers))
        eprint("\n[DRY RUN] Exiting without making actual API call")
        sys.exit(0)

    # Exchange JWT for installation token
    token_data: Dict[str, Any]
    response_headers: Dict[str, str]
    token_data, response_headers = make_api_request(
        endpoint,
        jwt_token,
        user_agent,
        debug,
        show_headers
    )

    return token_data


def natural_sort_key(s: str) -> List[Union[int, str]]:
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

    def __init__(self, base_dir: Path, no_fuzzy: bool = False) -> None:
        """
        Initialize the fuzzy completer.

        Args:
            base_dir: Starting directory for path completion
            no_fuzzy: If True, use prefix-only matching instead of fuzzy matching
        """
        self.base_dir: Path = base_dir
        self.no_fuzzy: bool = no_fuzzy
        from rapidfuzz import fuzz, process
        self.fuzz: Any = fuzz
        self.process: Any = process
        # Sentinel values for flow control without exposing conditionals
        self._EMPTY_RESULT: List[Tuple[str, float, Path]] = []
        self._NO_EARLY_EXIT = object()

    def _expand_path(self, path_str: str) -> Path:
        """Expand ~ and $HOME in path string."""
        expanded = path_str.replace('$HOME', str(Path.home()))
        return Path(expanded).expanduser()

    def _get_candidates(self, directory: Path, is_final_segment: bool) -> List[Path]:
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

        candidates: List[Path] = []
        try:
            for item in directory.iterdir():
                if item.is_dir():
                    candidates.append(item)
                elif is_final_segment and item.is_file() and item.suffix == '.pem':
                    candidates.append(item)
        except PermissionError:
            pass

        return candidates

    def _check_query_empty(self, query: str) -> bool:
        """Check if query is empty."""
        return not query

    def _handle_empty_query_or_continue(self, query: str) -> Union[List[Tuple[str, float, Path]], Any]:
        """Return empty list for empty query, sentinel to continue otherwise."""
        return self._EMPTY_RESULT if self._check_query_empty(query) else self._NO_EARLY_EXIT

    def _check_query_has_uppercase(self, query: str) -> bool:
        """Check if query contains any uppercase characters."""
        return any(c.isupper() for c in query)

    def _find_case_sensitive_prefix_matches(self, query: str, candidates: List[Path]) -> List[Path]:
        """Find candidates with case-sensitive prefix match."""
        return [c for c in candidates if c.name.startswith(query)]

    def _find_case_insensitive_prefix_matches(self, query: str, candidates: List[Path]) -> List[Path]:
        """Find candidates with case-insensitive prefix match."""
        query_lower: str = query.lower()
        return [c for c in candidates if c.name.lower().startswith(query_lower)]

    def _select_prefix_match_strategy(self, query: str, candidates: List[Path]) -> List[Path]:
        """Select and apply appropriate prefix matching strategy based on query case."""
        query_has_upper = self._check_query_has_uppercase(query)
        return (self._find_case_sensitive_prefix_matches(query, candidates)
                if query_has_upper
                else self._find_case_insensitive_prefix_matches(query, candidates))

    def _check_matches_empty(self, matches: List[Path]) -> bool:
        """Check if matches list is empty."""
        return not matches

    def _handle_no_matches_or_continue(self, matches: List[Path]) -> Union[List[Tuple[str, float, Path]], Any]:
        """Return empty list if no matches, sentinel to continue otherwise."""
        return self._EMPTY_RESULT if self._check_matches_empty(matches) else self._NO_EARLY_EXIT

    def _score_prefix_matches(self, matches: List[Path]) -> List[Tuple[str, float, Path]]:
        """Assign uniform score to all prefix matches."""
        return [(c.name, 100.0, c) for c in matches]

    def _perform_prefix_matching_workflow(self, matches: List[Path]) -> List[Tuple[str, float, Path]]:
        """Execute prefix matching workflow: check for no matches then score."""
        no_matches_result = self._handle_no_matches_or_continue(matches)
        return no_matches_result if no_matches_result is not self._NO_EARLY_EXIT else self._score_prefix_matches(matches)

    def _perform_prefix_matching(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Complete prefix matching workflow with internal decision-making."""
        matches = self._select_prefix_match_strategy(query, candidates)
        return self._perform_prefix_matching_workflow(matches)

    def _check_ordered_characters(self, query_str: str, target_str: str) -> bool:
        """Check if all characters in query appear in order in target."""
        query_lower = query_str.lower()
        target_lower = target_str.lower()
        query_idx = 0
        for char in target_lower:
            if query_idx < len(query_lower) and char == query_lower[query_idx]:
                query_idx += 1
        return query_idx == len(query_lower)

    def _filter_by_ordered_characters(self, query: str, candidates: List[Path]) -> List[Path]:
        """Filter candidates to only those with query characters in order."""
        return [c for c in candidates if self._check_ordered_characters(query, c.name)]

    def _extract_names_from_candidates(self, candidates: List[Path]) -> List[str]:
        """Extract name strings from candidate paths."""
        return [c.name for c in candidates]

    def _perform_fuzzy_scoring(self, query: str, names: List[str]) -> List[Tuple[str, float, int]]:
        """Score candidates using fuzzy matching algorithm."""
        return self.process.extract(query, names, scorer=self.fuzz.QRatio, limit=None)

    def _create_name_to_path_lookup(self, candidates: List[Path]) -> Dict[str, Path]:
        """Create dictionary mapping candidate names to paths."""
        return {c.name: c for c in candidates}

    def _check_has_prefix_match(self, name: str, query: str) -> bool:
        """Check if name starts with query (case-insensitive)."""
        return name.lower().startswith(query.lower())

    def _calculate_adjusted_score(self, name: str, query: str, base_score: float) -> float:
        """Calculate score with prefix bonus applied internally."""
        return base_score + 50.0 if self._check_has_prefix_match(name, query) else base_score

    def _apply_prefix_bonus_to_match(self, name: str, score: float, query: str, lookup: Dict[str, Path]) -> Tuple[str, float, Path]:
        """Apply prefix bonus to a single match and return result tuple."""
        path = lookup[name]
        adjusted_score = self._calculate_adjusted_score(name, query, score)
        return (name, adjusted_score, path)

    def _apply_prefix_bonuses(self, matches: List[Tuple[str, float, int]], query: str, lookup: Dict[str, Path]) -> List[Tuple[str, float, Path]]:
        """Apply prefix bonus to all matches and return adjusted results."""
        return [self._apply_prefix_bonus_to_match(name, score, query, lookup) for name, score, _ in matches]

    def _continue_with_fuzzy_scoring(self, valid_candidates: List[Path], query: str) -> List[Tuple[str, float, Path]]:
        """Continue with fuzzy scoring after validation."""
        names = self._extract_names_from_candidates(valid_candidates)
        matches = self._perform_fuzzy_scoring(query, names)
        lookup = self._create_name_to_path_lookup(valid_candidates)
        return self._apply_prefix_bonuses(matches, query, lookup)

    def _perform_fuzzy_matching_workflow(self, valid_candidates: List[Path], query: str) -> List[Tuple[str, float, Path]]:
        """Execute fuzzy matching workflow: check for no matches then score."""
        no_matches_result = self._handle_no_matches_or_continue(valid_candidates)
        return no_matches_result if no_matches_result is not self._NO_EARLY_EXIT else self._continue_with_fuzzy_scoring(valid_candidates, query)

    def _perform_fuzzy_matching(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Complete fuzzy matching workflow with internal decision-making."""
        valid_candidates = self._filter_by_ordered_characters(query, candidates)
        return self._perform_fuzzy_matching_workflow(valid_candidates, query)

    def _select_matching_strategy(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Dispatch to appropriate matching strategy (prefix or fuzzy) based on mode."""
        return (self._perform_prefix_matching(query, candidates)
                if self.no_fuzzy
                else self._perform_fuzzy_matching(query, candidates))

    def _check_is_pem_file(self, path: Path) -> bool:
        """Check if path is a PEM file."""
        return path.is_file() and path.suffix.lower() == '.pem'

    def _separate_pem_files(self, results: List[Tuple[str, float, Path]]) -> Tuple[List[Tuple[str, float, Path]], List[Tuple[str, float, Path]]]:
        """Separate results into PEM files and other matches."""
        pem_results = [(name, score, path) for name, score, path in results if self._check_is_pem_file(path)]
        other_results = [(name, score, path) for name, score, path in results if not self._check_is_pem_file(path)]
        return pem_results, other_results

    def _sort_by_score_and_name(self, results: List[Tuple[str, float, Path]]) -> None:
        """Sort results by score (descending) then natural sort (in-place)."""
        results.sort(key=lambda x: (-x[1], natural_sort_key(x[0])))

    def _organize_and_sort_results(self, results: List[Tuple[str, float, Path]]) -> List[Tuple[str, float, Path]]:
        """Separate PEM files, sort each group, and combine with PEM files first."""
        pem_results, other_results = self._separate_pem_files(results)
        self._sort_by_score_and_name(pem_results)
        self._sort_by_score_and_name(other_results)
        return pem_results + other_results

    def _continue_with_matching(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Continue with matching strategy selection and result organization."""
        matching_results = self._select_matching_strategy(query, candidates)
        return self._organize_and_sort_results(matching_results)

    def _dispatch_to_matching_or_return_early(self, empty_query_result: Union[List[Tuple[str, float, Path]], Any], query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Dispatch to matching workflow or return early exit result (decision made internally)."""
        return empty_query_result if empty_query_result is not self._NO_EARLY_EXIT else self._continue_with_matching(query, candidates)

    def _fuzzy_match(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """
        Perform fuzzy matching on candidates.

        Args:
            query: Search query string
            candidates: List of Path objects to match against

        Returns:
            List of tuples (name, score, path) with PEM files first (sorted by score then natural sort),
            then other matches (sorted by score then natural sort)
        """
        empty_query_result = self._handle_empty_query_or_continue(query)
        return self._dispatch_to_matching_or_return_early(empty_query_result, query, candidates)

    def get_completions(self, document: Any, complete_event: Any) -> Iterator[Any]:
        """
        Generate completions for the current document state.

        Args:
            document: The prompt_toolkit Document object
            complete_event: The completion event

        Yields:
            Completion objects for matching candidates
        """
        from prompt_toolkit.completion import Completion

        text: str = document.text_before_cursor

        # Parse the path into components
        if '/' in text:
            # Split into directory parts and final query
            parts: List[str] = text.split('/')
            final_query: str = parts[-1]
            dir_parts: List[str] = parts[:-1]

            # Build the directory path - expand ~ and $HOME for internal use
            current_dir: Path
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

                # For intermediate directories, we need to match even with empty part
                # Otherwise, use fuzzy matching that requires typing
                if part:
                    matches = self._fuzzy_match(part, subdirs)
                    if matches:
                        # Use best match
                        current_dir = matches[0][2]
                    else:
                        return
                else:
                    # Empty part in the middle shouldn't happen, but handle it
                    return

            # Get candidates for final segment (includes .pem files)
            # This is where we search for the final_query
            candidates: List[Path] = self._get_candidates(current_dir, True)

            # Special case: if final_query is empty (path ends with /),
            # show all PEM files first, then subdirectories, all in natural order
            if not final_query:
                # Separate PEM files and directories
                pem_files: List[Path] = [c for c in candidates if c.is_file() and c.suffix.lower() == '.pem']
                directories: List[Path] = [c for c in candidates if c.is_dir()]

                # Sort both in natural order
                pem_files.sort(key=lambda p: natural_sort_key(p.name))
                directories.sort(key=lambda p: natural_sort_key(p.name))

                # Yield PEM files first
                for path in pem_files:
                    yield Completion(
                        path.name,
                        start_position=0,
                        display=path.name
                    )

                # Then yield directories
                for path in directories:
                    yield Completion(
                        path.name + '/',
                        start_position=0,
                        display=path.name + '/'
                    )
            else:
                # Normal fuzzy matching
                fuzzy_matches: List[Tuple[str, float, Path]] = self._fuzzy_match(final_query, candidates)

                # Generate completions
                for name, score, path in fuzzy_matches:
                    completion_text: str
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
            # No slash - don't show completions for ~ alone
            if text == '~':
                # User typed just ~, don't show any completions
                return
            elif text.startswith('~') and len(text) > 1:
                # User typed ~something (but no slash yet)
                # Don't show completions until they type ~/
                return
            else:
                # No slash, no ~ - match in base directory
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

    async def get_completions_async(self, document: Any, complete_event: Any) -> Any:
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


def normalize_completion_flags(no_path_completion: bool, no_fuzzy: bool, enable_path_completion: bool) -> Tuple[bool, bool]:
    """Normalize completion flags based on no_path_completion setting."""
    if no_path_completion:
        return True, False
    return no_fuzzy, enable_path_completion


def select_editing_mode_by_string(mode_str: str, EditingMode: Any) -> Any:
    """Select editing mode enum value based on string."""
    if mode_str == 'vi':
        return EditingMode.VI
    else:
        return EditingMode.EMACS


def create_completer_for_path_mode(enable_path_completion: bool, no_fuzzy: bool, os: Any) -> Optional[Any]:
    """Create completer based on path completion mode."""
    if enable_path_completion:
        base_dir = Path(os.getcwd())
        return FuzzyPemCompleter(base_dir, no_fuzzy=no_fuzzy)
    else:
        return None


def create_toolbar_display(flash_error: bool, error_message: str, HTML: Any) -> Any:
    """Create toolbar display based on error state."""
    if flash_error:
        return HTML('<style bg="ansired" fg="ansiblack">  {}  </style>').format(error_message)
    elif error_message:
        return HTML('<style fg="ansired">  {}  </style>').format(error_message)
    return ""


def select_validator_for_mode(enable_path_completion: bool, validator: Any) -> Optional[Any]:
    """Select validator based on path completion mode."""
    if enable_path_completion:
        return validator
    else:
        return None


def select_toolbar_for_modes(enable_path_completion: bool, no_path_completion: bool, validator_func: Optional[Any], bottom_toolbar: Callable[[], Any]) -> Optional[Callable[[], Any]]:
    """Select toolbar function based on validation modes."""
    if enable_path_completion or no_path_completion or validator_func:
        return bottom_toolbar
    else:
        return None


def attach_no_path_completion_handler(session: Any, state: Any) -> None:
    """Attach text change handler for no_path_completion mode."""
    def on_text_changed(_: Any) -> None:
        state.error_message = ""
    session.default_buffer.on_text_changed += on_text_changed


def attach_auto_expansion_handler(session: Any, completer: Any) -> None:
    """Attach auto-expansion handler for path completion."""
    def on_text_changed(_: Any) -> None:
        buf = session.default_buffer
        text = buf.text
        if buf.complete_state:
            return
        if text and not text.endswith('/') and '/' not in text[:-1] and text not in ('~', '$HOME'):
            try:
                completions = list(completer.get_completions(buf.document, None))
                if len(completions) == 1:
                    completion = completions[0]
                    if completion.text.endswith('/'):
                        buf.text = completion.text
                        buf.cursor_position = len(completion.text)
            except Exception:
                pass
    session.default_buffer.on_text_changed += on_text_changed


def attach_text_handlers_for_modes(session: Any, no_path_completion: bool, enable_path_completion: bool, completer: Optional[Any], state: Any) -> None:
    """Attach appropriate text change handlers based on modes."""
    if no_path_completion:
        attach_no_path_completion_handler(session, state)
    if enable_path_completion and completer:
        attach_auto_expansion_handler(session, completer)


def prompt_with_session(session: Any) -> str:
    """Prompt user with session and return stripped result."""
    result = session.prompt()
    return result.strip()


def handle_import_error_with_fallback(e: Exception, prompt_text: str) -> str:
    """Handle ImportError by falling back to basic input."""
    eprint(f"Warning: Advanced input features unavailable ({e})")
    eprint(prompt_text, end='')
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        eprint()
        fatal_error("Input cancelled by user")


def handle_interrupt_error() -> NoReturn:
    """Handle keyboard interrupt by showing message and exiting."""
    eprint()
    fatal_error("Input cancelled by user")


def prompt_for_input(
    prompt_text: str,
    enable_path_completion: bool = False,
    validator_func: Optional[Callable[[str], None]] = None,
    no_fuzzy: bool = False,
    no_path_completion: bool = False
) -> str:
    """
    Prompt user for input on stderr with rich line editing.

    Args:
        prompt_text: The prompt to display
        enable_path_completion: Enable file path autocompletion with fuzzy matching
        validator_func: Optional validation function for non-path inputs
        no_fuzzy: Use prefix-only matching instead of fuzzy matching
        no_path_completion: Disable path completion entirely and only validate

    Returns:
        User input string
    """
    no_fuzzy, enable_path_completion = normalize_completion_flags(no_path_completion, no_fuzzy, enable_path_completion)
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.enums import EditingMode
        from prompt_toolkit.output import create_output
        from prompt_toolkit.validation import Validator, ValidationError as PTValidationError
        from prompt_toolkit.formatted_text import HTML
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.keys import Keys
        import os
        import threading
        import time

        mode_str = detect_editing_mode_from_inputrc()
        editing_mode = select_editing_mode_by_string(mode_str, EditingMode)
        completer = create_completer_for_path_mode(enable_path_completion, no_fuzzy, os)
        output = create_output(stdout=sys.stderr)

        class ValidationState:
            def __init__(self) -> None:
                self.error_message: str = ""
                self.flash_error: bool = False
                self.flash_thread: Optional[threading.Thread] = None
                self.yank_buffer: str = ""

        state = ValidationState()

        def bottom_toolbar() -> Any:
            return create_toolbar_display(state.flash_error, state.error_message, HTML)

        # Helper functions for validation logic
        def clear_error_state() -> None:
            """Clear error message at the start of validation."""
            state.error_message = ""

        def check_if_text_empty(text: str) -> bool:
            """Check if text is empty (validation should be skipped)."""
            return not text

        def expand_home_in_path(text: str) -> Path:
            """Expand $HOME and ~ in path string."""
            expanded = text.replace('$HOME', str(Path.home()))
            return Path(expanded).expanduser()

        def make_path_absolute_from_cwd(path: Path) -> Path:
            """Make path absolute if relative, using current working directory."""
            return path if path.is_absolute() else Path(os.getcwd()) / path

        def raise_validation_error_with_state(message: str) -> NoReturn:
            """Set error state and raise validation error (never returns)."""
            state.error_message = message
            raise PTValidationError(message=message)

        def validate_path_exists_or_fail(path: Path) -> None:
            """Validate that path exists, raise error if not."""
            if not path.exists():
                raise_validation_error_with_state("file does not exist")

        def validate_path_is_file_or_fail(path: Path) -> None:
            """Validate that path is a regular file, raise error if not."""
            if not path.is_file():
                raise_validation_error_with_state("not a regular file")

        def validate_path_is_readable_or_fail(path: Path) -> None:
            """Validate that path is readable, raise error if not."""
            try:
                with open(path, 'r'):
                    pass
            except (PermissionError, OSError):
                raise_validation_error_with_state("file is not readable")

        def perform_no_path_completion_validation(expanded_path: Path) -> None:
            """Complete validation workflow for no_path_completion mode."""
            absolute_path = make_path_absolute_from_cwd(expanded_path)
            validate_path_exists_or_fail(absolute_path)
            validate_path_is_file_or_fail(absolute_path)
            validate_path_is_readable_or_fail(absolute_path)

        def determine_base_directory_for_text(text: str) -> Path:
            """Determine the base directory based on text prefix."""
            if text.startswith('/'):
                return Path('/')
            elif text.startswith('~/') or text.startswith('$HOME/'):
                return Path.home()
            else:
                return Path(os.getcwd())

        def has_ordered_characters_match(query_str: str, target_str: str) -> bool:
            """Check if query characters appear in order in target (case-insensitive)."""
            query_lower = query_str.lower()
            target_lower = target_str.lower()
            query_idx = 0
            for char in target_lower:
                if query_idx < len(query_lower) and char == query_lower[query_idx]:
                    query_idx += 1
            return query_idx == len(query_lower)

        def find_prefix_matches_case_sensitive(query: str, candidates: List[Path]) -> List[Path]:
            """Find candidates matching query prefix with case sensitivity."""
            return [c for c in candidates if c.name.startswith(query)]

        def find_prefix_matches_case_insensitive(query: str, candidates: List[Path]) -> List[Path]:
            """Find candidates matching query prefix without case sensitivity."""
            query_lower = query.lower()
            return [c for c in candidates if c.name.lower().startswith(query_lower)]

        def select_prefix_matching_strategy(query: str, candidates: List[Path]) -> List[Path]:
            """Select and apply prefix matching strategy based on query case."""
            query_has_upper = any(c.isupper() for c in query)
            if query_has_upper:
                return find_prefix_matches_case_sensitive(query, candidates)
            else:
                return find_prefix_matches_case_insensitive(query, candidates)

        def find_fuzzy_matches(query: str, candidates: List[Path]) -> List[Path]:
            """Find candidates matching query using fuzzy (ordered characters) matching."""
            return [c for c in candidates if has_ordered_characters_match(query, c.name)]

        def apply_matching_strategy(query: str, candidates: List[Path]) -> List[Path]:
            """Apply appropriate matching strategy (prefix or fuzzy) based on mode."""
            if no_fuzzy:
                return select_prefix_matching_strategy(query, candidates)
            else:
                return find_fuzzy_matches(query, candidates)

        def find_exact_directory_match(part: str, subdirs: List[Path]) -> Optional[Path]:
            """Find exact name match in subdirectory list."""
            for subdir in subdirs:
                if subdir.name == part:
                    return subdir
            return None

        def find_first_matching_directory(part: str, subdirs: List[Path]) -> Optional[Path]:
            """Find first matching subdirectory using current matching strategy."""
            matches = apply_matching_strategy(part, subdirs)
            if matches:
                return matches[0]
            else:
                return None

        def resolve_directory_segment(part: str, subdirs: List[Path]) -> Optional[Path]:
            """Resolve a single directory path segment to a matched directory."""
            exact = find_exact_directory_match(part, subdirs)
            if exact:
                return exact
            else:
                return find_first_matching_directory(part, subdirs)

        def get_subdirectories_from_path(current_dir: Path) -> List[Path]:
            """Get list of subdirectories from path, empty list if path doesn't exist."""
            if current_dir.exists():
                return [p for p in current_dir.iterdir() if p.is_dir()]
            else:
                return []

        def check_skip_directory_part(i: int, part: str) -> bool:
            """Determine if directory part should be skipped during navigation."""
            if not part:
                return True
            if i == 0 and part in ('~', '$HOME'):
                return True
            return False

        def validate_directory_exists_for_query_or_fail(current_dir: Path, final_query: str) -> None:
            """Validate directory exists when there's a final query to match."""
            if not current_dir.exists() and final_query:
                raise_validation_error_with_state("no match")

        def validate_match_found_for_query_or_fail(matched: Optional[Path], final_query: str) -> None:
            """Validate that a match was found when there's a final query."""
            if not matched and final_query:
                raise_validation_error_with_state("no match")

        def navigate_one_directory_segment(i: int, part: str, current_dir: Path, final_query: str) -> Path:
            """Navigate through one directory segment, returning updated current directory."""
            if check_skip_directory_part(i, part):
                return current_dir

            validate_directory_exists_for_query_or_fail(current_dir, final_query)
            subdirs = get_subdirectories_from_path(current_dir)
            matched = resolve_directory_segment(part, subdirs)
            validate_match_found_for_query_or_fail(matched, final_query)
            if matched:
                return matched
            else:
                return current_dir

        def navigate_through_directory_parts(dir_parts: List[str], base_dir: Path, final_query: str) -> Path:
            """Navigate through all directory parts, returning final directory."""
            current_dir = base_dir
            for i, part in enumerate(dir_parts):
                current_dir = navigate_one_directory_segment(i, part, current_dir, final_query)
            return current_dir

        def get_path_validation_candidates_or_fail(current_dir: Path) -> List[Path]:
            """Get list of validation candidates (directories and .pem files) from directory."""
            try:
                return [item for item in current_dir.iterdir()
                       if item.is_dir() or (item.is_file() and item.suffix == '.pem')]
            except PermissionError:
                raise_validation_error_with_state("no match")

        def validate_directory_exists_or_fail(current_dir: Path) -> None:
            """Validate directory exists, raise 'no match' error if not."""
            if not current_dir.exists():
                raise_validation_error_with_state("no match")

        def validate_candidates_not_empty_or_fail(candidates: List[Path]) -> None:
            """Validate that candidates list is not empty, raise error if empty."""
            if not candidates:
                raise_validation_error_with_state("no match")

        def validate_query_has_match_or_fail(query: str, candidates: List[Path]) -> None:
            """Validate that query matches at least one candidate, raise error if not."""
            matches = apply_matching_strategy(query, candidates)
            if not matches:
                raise_validation_error_with_state("no match")

        def validate_final_query_segment(final_query: str, current_dir: Path) -> None:
            """Validate final query segment against candidates in directory."""
            validate_directory_exists_or_fail(current_dir)
            candidates = get_path_validation_candidates_or_fail(current_dir)
            validate_candidates_not_empty_or_fail(candidates)
            validate_query_has_match_or_fail(final_query, candidates)

        def parse_path_components(text: str) -> Tuple[List[str], str]:
            """Parse path into directory parts and final query segment."""
            parts = text.split('/')
            return parts[:-1], parts[-1]

        def validate_final_query_if_present(final_query: str, current_dir: Path) -> None:
            """Validate final query segment if it's not empty."""
            if final_query:
                validate_final_query_segment(final_query, current_dir)

        def validate_multi_segment_path(text: str, base_dir: Path) -> None:
            """Validate a path containing directory separators."""
            dir_parts, final_query = parse_path_components(text)
            current_dir = navigate_through_directory_parts(dir_parts, base_dir, final_query)
            validate_final_query_if_present(final_query, current_dir)

        def check_if_special_home_marker(text: str) -> bool:
            """Check if text is a special home directory marker."""
            return text in ('~', '$HOME')

        def validate_non_special_single_segment(text: str, base_dir: Path) -> None:
            """Validate single segment path that is not a special marker."""
            validate_directory_exists_or_fail(base_dir)
            candidates = get_path_validation_candidates_or_fail(base_dir)
            validate_candidates_not_empty_or_fail(candidates)
            validate_query_has_match_or_fail(text, candidates)

        def validate_single_segment_path(text: str, base_dir: Path) -> None:
            """Validate a simple path with no directory separators."""
            if check_if_special_home_marker(text):
                return
            validate_non_special_single_segment(text, base_dir)

        def dispatch_path_validation_by_structure(text: str, base_dir: Path) -> None:
            """Dispatch to appropriate validation based on path structure."""
            if '/' in text:
                validate_multi_segment_path(text, base_dir)
            else:
                validate_single_segment_path(text, base_dir)

        def perform_path_completion_validation(text: str) -> None:
            """Complete validation workflow for path completion mode."""
            base_dir = determine_base_directory_for_text(text)
            dispatch_path_validation_by_structure(text, base_dir)

        def dispatch_validation_by_completion_mode(expanded_path: Path, text: str) -> None:
            """Dispatch to appropriate validation handler based on completion mode."""
            if no_path_completion:
                perform_no_path_completion_validation(expanded_path)
            else:
                perform_path_completion_validation(text)

        def execute_path_validation_with_exception_handling(text: str) -> None:
            """Execute path validation with proper exception handling."""
            try:
                expanded_path = expand_home_in_path(text)
                dispatch_validation_by_completion_mode(expanded_path, text)
            except PTValidationError:
                raise
            except Exception:
                pass

        def check_if_path_validation_enabled() -> bool:
            """Check if path validation is enabled in current mode."""
            return enable_path_completion or no_path_completion

        def dispatch_validation_by_mode(text: str) -> None:
            """Dispatch validation based on whether path validation is enabled."""
            if check_if_path_validation_enabled():
                execute_path_validation_with_exception_handling(text)

        def execute_validation_workflow(text: str) -> None:
            """Execute the complete validation workflow based on mode."""
            dispatch_validation_by_mode(text)

        def handle_empty_text_or_validate(text: str) -> None:
            """Handle empty text case or proceed with validation."""
            if check_if_text_empty(text):
                return
            execute_validation_workflow(text)

        # Validator for inputs
        class InputValidator(Validator):
            def validate(self, document: Any) -> None:
                """Validate input according to current mode and configuration."""
                text = document.text.strip()
                clear_error_state()
                handle_empty_text_or_validate(text)

        validator = InputValidator()

        # Custom key bindings
        kb = KeyBindings()

        @kb.add(Keys.Backspace)
        def handle_backspace(event: Any) -> None:
            """Handle backspace - keep completions visible."""
            buf = event.app.current_buffer
            if buf.cursor_position > 0:
                buf.delete_before_cursor(count=1)
                # Trigger completions if path completion is enabled
                if enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(Keys.ControlW)
        def handle_ctrl_w(event: Any) -> None:
            """Handle Ctrl-W (delete word) - keep completions visible and save to yank buffer."""
            buf = event.app.current_buffer
            # Delete word before cursor (standard behavior)
            if buf.text:
                pos = buf.cursor_position
                # Find start of word
                text_before = buf.text[:pos]

                # Skip trailing whitespace
                while text_before and text_before[-1] in ' \t':
                    text_before = text_before[:-1]
                # Delete trailing slash if present
                if text_before and text_before[-1] == '/':
                    text_before = text_before[:-1]
                # Delete word characters
                while text_before and text_before[-1] not in ' \t/':
                    text_before = text_before[:-1]

                new_pos = len(text_before)

                # Save deleted text to yank buffer
                deleted_text = buf.text[new_pos:pos]
                if deleted_text:
                    state.yank_buffer = deleted_text

                buf.cursor_position = new_pos
                buf.text = text_before + buf.text[pos:]

                # Trigger completions if path completion is enabled
                if enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(Keys.ControlU)
        def handle_ctrl_u(event: Any) -> None:
            """Handle Ctrl-U (delete from beginning of line to cursor) - save to yank buffer."""
            buf = event.app.current_buffer
            if buf.cursor_position > 0:
                # Save deleted text to yank buffer
                deleted_text = buf.text[:buf.cursor_position]
                if deleted_text:
                    state.yank_buffer = deleted_text

                # Delete from start to cursor
                buf.text = buf.text[buf.cursor_position:]
                buf.cursor_position = 0

                # Trigger completions if path completion is enabled
                if enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(Keys.ControlY)
        def handle_ctrl_y(event: Any) -> None:
            """Handle Ctrl-Y (yank/paste) - paste back last deleted text."""
            buf = event.app.current_buffer
            if state.yank_buffer:
                # Insert yanked text at cursor position
                pos = buf.cursor_position
                buf.text = buf.text[:pos] + state.yank_buffer + buf.text[pos:]
                buf.cursor_position = pos + len(state.yank_buffer)

                # Trigger completions if path completion is enabled
                if enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        def check_ordered_chars(query_str: str, target_str: str) -> bool:
            """Check if query characters appear in order in target (case-insensitive)."""
            query_lower: str = query_str.lower()
            target_lower: str = target_str.lower()
            query_idx: int = 0
            for char in target_lower:
                query_idx += (query_idx < len(query_lower) and char == query_lower[query_idx])
            return query_idx == len(query_lower)

        def match_prefix_case_sensitive(query_str: str, target_str: str) -> bool:
            """Match using case-sensitive prefix matching."""
            return target_str.startswith(query_str)

        def match_prefix_case_insensitive(query_str: str, target_str: str) -> bool:
            """Match using case-insensitive prefix matching."""
            return target_str.lower().startswith(query_str.lower())

        def select_prefix_matcher(query_str: str) -> Callable[[str, str], bool]:
            """Select appropriate prefix matcher based on query case."""
            query_has_upper = any(c.isupper() for c in query_str)
            return match_prefix_case_sensitive if query_has_upper else match_prefix_case_insensitive

        def match_by_prefix_mode(query_str: str, target_str: str) -> bool:
            """Match using prefix-only matching with case sensitivity rules."""
            matcher = select_prefix_matcher(query_str)
            return matcher(query_str, target_str)

        def match_query_against_target(query_str: str, target_str: str) -> bool:
            """Match query against target based on current fuzzy mode setting."""
            return match_by_prefix_mode(query_str, target_str) if no_fuzzy else check_ordered_chars(query_str, target_str)

        def collect_directory_candidates(directory: Path) -> List[Path]:
            """Collect directory items from a path, returning empty list if unavailable."""
            return [item for item in directory.iterdir() if item.is_dir()] if directory.exists() else []

        def collect_final_segment_candidates(directory: Path) -> List[Path]:
            """Collect both directories and .pem files from a path."""
            return [item for item in directory.iterdir()
                   if item.is_dir() or (item.is_file() and item.suffix == '.pem')] if directory.exists() else []

        def collect_candidates_for_segment(directory: Path, is_final_segment: bool) -> List[Path]:
            """Collect candidates based on whether this is the final path segment."""
            return collect_final_segment_candidates(directory) if is_final_segment else collect_directory_candidates(directory)

        def find_exact_match(candidates: List[Path], name: str) -> Optional[Path]:
            """Find exact name match in candidate list."""
            return next((c for c in candidates if c.name == name), None)

        def filter_candidates_by_query(candidates: List[Path], query: str) -> List[Path]:
            """Filter candidates to those matching the query."""
            return [c for c in candidates if match_query_against_target(query, c.name)]

        def select_first_candidate(candidates: List[Path]) -> Path:
            """Select the first candidate from a list."""
            return candidates[0]

        def score_and_select_best_fuzzy_match(candidates: List[Path], query: str) -> Optional[Path]:
            """Score candidates and return the best fuzzy match."""
            from rapidfuzz import fuzz, process
            names: List[str] = [c.name for c in candidates]
            matches: List[Tuple[str, float, int]] = process.extract(query, names, scorer=fuzz.QRatio, limit=1)
            return next((c for c in candidates if c.name == matches[0][0]), None) if matches else None

        def select_best_fuzzy_candidate(candidates: List[Path], query: str) -> Path:
            """Select best candidate using fuzzy scoring."""
            return score_and_select_best_fuzzy_match(candidates, query) or candidates[0]

        def select_candidate_by_mode(candidates: List[Path], query: str) -> Path:
            """Select best candidate based on current fuzzy mode setting."""
            return select_first_candidate(candidates) if no_fuzzy else select_best_fuzzy_candidate(candidates, query)

        def resolve_segment_match(candidates: List[Path], segment: str) -> Optional[Path]:
            """Resolve a path segment to a matched candidate path."""
            exact = find_exact_match(candidates, segment)
            return exact or (lambda filtered: select_candidate_by_mode(filtered, segment) if filtered else None)(filter_candidates_by_query(candidates, segment))

        def determine_root_for_absolute_path() -> Tuple[Path, int, List[str]]:
            """Determine base directory for absolute paths starting with /."""
            return (Path('/'), 1, [''])

        def determine_root_for_tilde_path() -> Tuple[Path, int, List[str]]:
            """Determine base directory for paths starting with ~/."""
            return (Path.home(), 1, ['~'])

        def determine_root_for_home_path() -> Tuple[Path, int, List[str]]:
            """Determine base directory for paths starting with $HOME/."""
            return (Path.home(), 1, ['$HOME'])

        def determine_root_for_relative_path() -> Tuple[Path, int, List[str]]:
            """Determine base directory for relative paths."""
            return (Path(os.getcwd()), 0, [])

        def select_path_root_handler(text: str) -> Callable[[], Tuple[Path, int, List[str]]]:
            """Select the appropriate root handler based on path prefix."""
            starts_with_tilde = text.startswith('~/')
            starts_with_home = text.startswith('$HOME/')
            starts_with_slash = text.startswith('/')

            return (determine_root_for_absolute_path if starts_with_slash else
                   determine_root_for_tilde_path if starts_with_tilde else
                   determine_root_for_home_path if starts_with_home else
                   determine_root_for_relative_path)

        def initialize_path_navigation(text: str) -> Tuple[Path, int, List[str]]:
            """Initialize base directory, start index, and unexpanded parts for path navigation."""
            handler = select_path_root_handler(text)
            return handler()

        def skip_empty_or_special_part(part: str) -> bool:
            """Determine if a path part should be skipped during navigation."""
            return not part or part in ('~', '$HOME')

        def build_formatted_path_result(unexpanded_parts: List[str], resolved_path: Path) -> Tuple[str, str]:
            """Build the final result tuple with unexpanded and expanded paths."""
            unexpanded = '/'.join(unexpanded_parts)
            return (unexpanded, str(resolved_path))

        def navigate_through_path_segments(parts: List[str], start_idx: int, initial_dir: Path, unexpanded_parts: List[str]) -> Optional[Tuple[Path, List[str]]]:
            """Navigate through all path segments, resolving each one."""
            current_dir = initial_dir

            for i in range(start_idx, len(parts)):
                part = parts[i]

                if skip_empty_or_special_part(part):
                    continue

                is_final = (i == len(parts) - 1)
                candidates = collect_candidates_for_segment(current_dir, is_final)
                matched = resolve_segment_match(candidates, part)

                if not matched:
                    return None

                current_dir = matched
                unexpanded_parts.append(matched.name)

            return (current_dir, unexpanded_parts)

        def resolve_multi_segment_path(text: str) -> Optional[Tuple[str, str]]:
            """Resolve a path with multiple segments (contains /)."""
            parts = text.split('/')
            current_dir, start_idx, unexpanded_parts = initialize_path_navigation(text)
            navigation_result = navigate_through_path_segments(parts, start_idx, current_dir, unexpanded_parts)
            return build_formatted_path_result(navigation_result[1], navigation_result[0]) if navigation_result else None

        def resolve_single_segment_path(text: str) -> Optional[Tuple[str, str]]:
            """Resolve a simple path with no directory separators."""
            base_dir = Path(os.getcwd())
            candidates = collect_final_segment_candidates(base_dir)
            exact = find_exact_match(candidates, text)

            if exact:
                return (text, str(exact))

            filtered = filter_candidates_by_query(candidates, text)
            return ((lambda m: (m.name, str(m)))(select_candidate_by_mode(filtered, text))) if filtered else None

        def dispatch_path_resolution(text: str) -> Optional[Tuple[str, str]]:
            """Dispatch to appropriate path resolution strategy based on path structure."""
            return resolve_multi_segment_path(text) if '/' in text else resolve_single_segment_path(text)

        def resolve_path_with_error_handling(text: str) -> Optional[Tuple[str, str]]:
            """Resolve path with exception handling, returning None on any error."""
            try:
                return dispatch_path_resolution(text)
            except Exception:
                return None

        def validate_path_resolution_preconditions(text: str) -> bool:
            """Check if preconditions for path resolution are met."""
            return bool(text and enable_path_completion)

        def resolve_fuzzy_path(text: str) -> Optional[Tuple[str, str]]:
            """Resolve a fuzzy path to an actual full path.

            Returns:
                Tuple of (unexpanded_path, expanded_path) or None if no match
            """
            return resolve_path_with_error_handling(text) if validate_path_resolution_preconditions(text) else None

        def check_if_path_mode_enabled() -> bool:
            """Check if any path mode is enabled."""
            return enable_path_completion or no_path_completion

        def check_if_text_is_empty(text: str) -> bool:
            """Check if text is empty."""
            return not text

        def select_validation_path_for_no_completion(text: str) -> str:
            """Return validation path for no_path_completion mode."""
            return text

        def update_buffer_with_resolved_path(buf: Any, unexpanded_path: str) -> None:
            """Update buffer text and cursor position with resolved path."""
            buf.text = unexpanded_path
            buf.cursor_position = len(unexpanded_path)

        def get_expanded_path_from_result(result: Tuple[str, str]) -> Tuple[str, str]:
            """Extract unexpanded and expanded paths from resolution result."""
            unexpanded_path, expanded_path = result
            return unexpanded_path, expanded_path

        def resolve_and_update_buffer_or_use_text(buf: Any, text: str) -> Tuple[str, str]:
            """Resolve fuzzy path and update buffer, or return original text."""
            result = resolve_fuzzy_path(text)
            if result:
                unexpanded_path, expanded_path = get_expanded_path_from_result(result)
                update_buffer_with_resolved_path(buf, unexpanded_path)
                return unexpanded_path, expanded_path
            else:
                return text, text

        def determine_validation_path_for_completion_mode(buf: Any, text: str) -> str:
            """Determine validation path based on completion mode."""
            if no_path_completion:
                return select_validation_path_for_no_completion(text)
            else:
                _, validation_path = resolve_and_update_buffer_or_use_text(buf, text)
                return validation_path

        def expand_home_variables(validation_path: str) -> str:
            """Expand $HOME variable in path string."""
            return validation_path.replace('$HOME', str(Path.home()))

        def expand_tilde_in_path(path_str: str) -> Path:
            """Expand tilde in path string to Path object."""
            return Path(path_str).expanduser()

        def make_absolute_if_relative(path: Path) -> Path:
            """Make path absolute if it's relative."""
            if not path.is_absolute():
                return Path(os.getcwd()) / path
            else:
                return path

        def set_error_and_abort(message: str) -> None:
            """Set error message in state (never returns normally)."""
            state.error_message = message

        def check_path_exists_or_abort(path: Path) -> bool:
            """Check if path exists, return True if exists, False if not."""
            return path.exists()

        def check_path_is_directory_or_abort(path: Path) -> bool:
            """Check if path is a directory, return True if directory, False if not."""
            return path.is_dir()

        def check_path_is_pem_file(path: Path) -> bool:
            """Check if path has .pem extension."""
            return path.suffix == '.pem'

        def validate_path_exists_or_abort(path: Path) -> bool:
            """Validate path exists, return False and set error if not."""
            if not check_path_exists_or_abort(path):
                set_error_and_abort("not a valid *.pem file name")
                return False
            return True

        def validate_path_not_directory_or_abort(path: Path) -> bool:
            """Validate path is not a directory, return False and set error if it is."""
            if check_path_is_directory_or_abort(path):
                set_error_and_abort("this is a directory, not a *.pem file")
                return False
            return True

        def validate_path_is_pem_or_abort(path: Path) -> bool:
            """Validate path is a .pem file, return False and set error if not."""
            if not check_path_is_pem_file(path):
                set_error_and_abort("not a valid *.pem file name")
                return False
            return True

        def perform_path_validation_checks(path: Path) -> bool:
            """Perform all path validation checks, return False on any failure."""
            return (validate_path_exists_or_abort(path) and
                   validate_path_not_directory_or_abort(path) and
                   validate_path_is_pem_or_abort(path))

        def validate_resolved_path_or_set_error(validation_path: str) -> bool:
            """Validate resolved path through all checks, return False on failure."""
            try:
                expanded = expand_home_variables(validation_path)
                path = expand_tilde_in_path(expanded)
                absolute_path = make_absolute_if_relative(path)
                return perform_path_validation_checks(absolute_path)
            except Exception:
                set_error_and_abort("not a valid *.pem file name")
                return False

        def handle_path_mode_validation(buf: Any, text: str) -> bool:
            """Handle validation for path modes, return False if validation fails."""
            if check_if_text_is_empty(text):
                return False
            validation_path = determine_validation_path_for_completion_mode(buf, text)
            return validate_resolved_path_or_set_error(validation_path)

        def extract_first_line_from_error(error: ValidationError) -> str:
            """Extract first line from ValidationError message."""
            return str(error).split('\n')[0]

        def validate_with_custom_validator_or_set_error(text: str) -> bool:
            """Validate using custom validator, return False if validation fails."""
            if validator_func:
                try:
                    validator_func(text)
                    return True
                except ValidationError as e:
                    set_error_and_abort(extract_first_line_from_error(e))
                    return False
            return True

        def handle_non_path_mode_validation(text: str) -> bool:
            """Handle validation for non-path modes, return False if validation fails."""
            return validate_with_custom_validator_or_set_error(text)

        def perform_validation_by_mode(buf: Any, text: str) -> bool:
            """Perform validation based on current mode, return False if validation fails."""
            if check_if_path_mode_enabled():
                return handle_path_mode_validation(buf, text)
            else:
                return handle_non_path_mode_validation(text)

        def accept_buffer_input(buf: Any) -> None:
            """Accept the buffer input."""
            buf.validate_and_handle()

        def validate_and_accept_if_valid(buf: Any, text: str) -> None:
            """Validate input and accept if valid."""
            if perform_validation_by_mode(buf, text):
                accept_buffer_input(buf)

        @kb.add(Keys.ControlM)  # Enter key
        def handle_enter(event: Any) -> None:
            """Handle Enter key - validate before accepting."""
            buf = event.app.current_buffer
            text = buf.text.strip()
            validate_and_accept_if_valid(buf, text)

        def check_if_should_flash_error(buf: Any) -> bool:
            """Check if error should be flashed."""
            return bool(enable_path_completion and state.error_message and not buf.complete_state)

        def enable_flash_error_state() -> None:
            """Enable flash error state."""
            state.flash_error = True

        def create_unflash_callback(event: Any) -> Callable[[], None]:
            """Create callback to unflash error after delay."""
            def unflash() -> None:
                time.sleep(0.5)
                state.flash_error = False
                event.app.invalidate()
            return unflash

        def check_if_flash_thread_is_inactive() -> bool:
            """Check if flash thread is None or not alive."""
            return state.flash_thread is None or not state.flash_thread.is_alive()

        def start_unflash_thread(unflash_callback: Callable[[], None]) -> None:
            """Start unflash thread with callback."""
            state.flash_thread = threading.Thread(target=unflash_callback, daemon=True)
            state.flash_thread.start()

        def start_unflash_thread_if_inactive(event: Any) -> None:
            """Start unflash thread if no active thread exists."""
            if check_if_flash_thread_is_inactive():
                unflash_callback = create_unflash_callback(event)
                start_unflash_thread(unflash_callback)

        def perform_error_flash(event: Any) -> None:
            """Perform error flash animation."""
            enable_flash_error_state()
            start_unflash_thread_if_inactive(event)

        def perform_normal_tab_completion(buf: Any) -> None:
            """Perform normal tab completion."""
            buf.complete_next()

        def handle_tab_based_on_state(buf: Any, event: Any) -> None:
            """Handle tab key based on current state."""
            if check_if_should_flash_error(buf):
                perform_error_flash(event)
            else:
                perform_normal_tab_completion(buf)

        @kb.add(Keys.ControlI)  # Tab key
        def handle_tab(event: Any) -> None:
            """Handle Tab key - show completions or flash error."""
            buf = event.app.current_buffer
            handle_tab_based_on_state(buf, event)

        selected_validator = select_validator_for_mode(enable_path_completion, validator)
        selected_toolbar = select_toolbar_for_modes(enable_path_completion, no_path_completion, validator_func, bottom_toolbar)

        session: PromptSession[str] = PromptSession(
            message=prompt_text,
            editing_mode=editing_mode,
            completer=completer,
            complete_while_typing=enable_path_completion,
            output=output,
            enable_history_search=False,
            validator=selected_validator,
            validate_while_typing=enable_path_completion,
            key_bindings=kb,
            bottom_toolbar=selected_toolbar,
            reserve_space_for_menu=8
        )

        attach_text_handlers_for_modes(session, no_path_completion, enable_path_completion, completer, state)
        return prompt_with_session(session)

    except ImportError as e:
        return handle_import_error_with_fallback(e, prompt_text)
    except (EOFError, KeyboardInterrupt):
        handle_interrupt_error()


def validate_and_collect_errors(
    client_id: str,
    pem_path: Path,
    installation_id: Optional[str],
    force: bool,
    jwt_only: bool
) -> List[str]:
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
    errors: List[str] = []

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
        '--no-fuzzy',
        action='store_true',
        help='Disable fuzzy matching; use prefix-only matching for path completion'
    )
    parser.add_argument(
        '--no-path-completion',
        action='store_true',
        help='Disable path completion entirely; only validate file after input'
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


def validate_command_line_args(args: argparse.Namespace) -> None:
    """Validate command-line arguments."""
    try:
        validate_jwt_expiry(args.jwt_expiry)
        validate_api_url(args.api_url)
    except ValidationError as e:
        fatal_error(str(e))


def collect_inputs(args: argparse.Namespace) -> Tuple[str, Path, str, Optional[str]]:
    """Collect inputs either interactively or from command-line arguments.

    Returns:
        Tuple of (client_id, pem_path, pem_path_str, installation_id)
    """
    is_interactive = not args.client_id or not args.pem_path or (not args.jwt and not args.installation_id)

    if is_interactive:
        return collect_inputs_interactively(args)
    else:
        return collect_inputs_from_args(args)


def prompt_for_client_id(force: bool) -> str:
    """Prompt user for GitHub App Client ID."""
    return prompt_for_input(
        "Enter GitHub App Client ID: ",
        enable_path_completion=False,
        validator_func=lambda text: validate_client_id(text, force)
    )


def prompt_for_pem_path(no_path_completion: bool, no_fuzzy: bool) -> str:
    """Prompt user for PEM file path."""
    use_path_completion = not no_path_completion
    use_fuzzy = not (no_fuzzy or no_path_completion)

    return prompt_for_input(
        "Enter path to private key PEM file: ",
        enable_path_completion=use_path_completion,
        no_fuzzy=not use_fuzzy,
        no_path_completion=no_path_completion
    )


def prompt_for_installation_id(force: bool) -> str:
    """Prompt user for Installation ID."""
    return prompt_for_input(
        "Enter Installation ID: ",
        enable_path_completion=False,
        validator_func=lambda text: validate_installation_id(text, force)
    )


def obtain_client_id(provided_id: Optional[str], force: bool) -> str:
    """
    Obtain Client ID either from provided value or by prompting.

    Args:
        provided_id: Client ID if provided via command line, None otherwise
        force: Skip validation if True

    Returns:
        Client ID string
    """
    if provided_id:
        return provided_id
    return prompt_for_client_id(force)


def obtain_pem_path_string(provided_path: Optional[str], no_path_completion: bool, no_fuzzy: bool) -> str:
    """
    Obtain PEM path string either from provided value or by prompting.

    Args:
        provided_path: PEM path if provided via command line, None otherwise
        no_path_completion: Disable path completion
        no_fuzzy: Use prefix-only matching

    Returns:
        PEM path string
    """
    if provided_path:
        return provided_path
    return prompt_for_pem_path(no_path_completion, no_fuzzy)


def expand_and_validate_pem_path(pem_path_str: str, force: bool) -> Path:
    """
    Expand PEM path string and validate the file.

    Args:
        pem_path_str: Path string to expand
        force: Skip format validation if True

    Returns:
        Expanded and validated Path object
    """
    try:
        pem_path = expand_path(pem_path_str)
    except Exception as e:
        fatal_error(f"Invalid file path: {e}")

    try:
        validate_pem_file(pem_path, force)
    except ValidationError as e:
        fatal_error(str(e))

    return pem_path


def obtain_installation_id(provided_id: Optional[str], jwt_mode: bool, force: bool) -> Optional[str]:
    """
    Obtain Installation ID either from provided value or by prompting.
    Returns None without prompting if in JWT-only mode.

    Args:
        provided_id: Installation ID if provided via command line, None otherwise
        jwt_mode: True if generating JWT only (no installation token needed)
        force: Skip validation if True

    Returns:
        Installation ID string or None
    """
    if jwt_mode:
        return provided_id
    if provided_id:
        return provided_id
    return prompt_for_installation_id(force)


def collect_inputs_interactively(args: argparse.Namespace) -> Tuple[str, Path, str, Optional[str]]:
    """
    Collect and validate inputs in interactive mode.

    Returns:
        Tuple of (client_id, pem_path, pem_path_str, installation_id)
    """
    client_id = obtain_client_id(args.client_id, args.force)
    pem_path_str = obtain_pem_path_string(args.pem_path, args.no_path_completion, args.no_fuzzy)
    pem_path = expand_and_validate_pem_path(pem_path_str, args.force)
    installation_id = obtain_installation_id(args.installation_id, args.jwt, args.force)
    return client_id, pem_path, pem_path_str, installation_id


def ensure_pem_path_provided(pem_path_str: Optional[str]) -> str:
    """Ensure PEM path is provided, exit if not.

    Args:
        pem_path_str: The PEM path string (may be None)

    Returns:
        The PEM path string (guaranteed non-None)
    """
    if not pem_path_str:
        fatal_error("PEM path is required")
    return pem_path_str


def ensure_client_id_provided(client_id: Optional[str]) -> str:
    """Ensure Client ID is provided, exit if not.

    Args:
        client_id: The client ID string (may be None)

    Returns:
        The client ID string (guaranteed non-None)
    """
    if not client_id:
        fatal_error("Client ID is required")
    return client_id


def expand_path_or_exit(pem_path_str: str) -> Path:
    """Expand path, exit with error message on failure.

    Args:
        pem_path_str: The path string to expand

    Returns:
        Expanded Path object
    """
    try:
        return expand_path(pem_path_str)
    except Exception as e:
        fatal_error(f"Invalid file path '{pem_path_str}': {e}")


def validate_all_or_exit(
    client_id: str,
    pem_path: Path,
    installation_id: Optional[str],
    force: bool,
    jwt_only: bool
) -> None:
    """Validate all inputs and exit with formatted errors if any fail.

    Args:
        client_id: GitHub App Client ID
        pem_path: Path to private key PEM file
        installation_id: Installation ID (can be None in JWT-only mode)
        force: Skip validation where allowed
        jwt_only: Whether running in JWT-only mode
    """
    validation_errors = validate_and_collect_errors(
        client_id=client_id,
        pem_path=pem_path,
        installation_id=installation_id,
        force=force,
        jwt_only=jwt_only
    )

    if validation_errors:
        eprint("Validation failed with the following error(s):\n")
        for i, error in enumerate(validation_errors, 1):
            indented_error = error.replace('\n', '\n  ')
            eprint(f"{i}. {indented_error}")
            if i < len(validation_errors):
                eprint()
        sys.exit(1)


def collect_inputs_from_args(args: argparse.Namespace) -> Tuple[str, Path, str, Optional[str]]:
    """Collect and validate inputs from command-line arguments.

    This function orchestrates the collection and validation process
    through a linear sequence of function calls. Each helper function
    makes its own decisions internally and handles errors by exiting.

    Returns:
        Tuple of (client_id, pem_path, pem_path_str, installation_id)
    """
    pem_path_str = ensure_pem_path_provided(args.pem_path)
    client_id = ensure_client_id_provided(args.client_id)
    pem_path = expand_path_or_exit(pem_path_str)
    validate_all_or_exit(client_id, pem_path, args.installation_id, args.force, args.jwt)
    return client_id, pem_path, pem_path_str, args.installation_id


def show_progress_and_debug_info(args: argparse.Namespace, client_id: str, pem_path_str: str, installation_id: Optional[str]) -> None:
    """Show progress message and debug information."""
    if not args.quiet:
        eprint(f"Reading private key from: {pem_path_str}")

    debug_print(f"Client ID: {client_id}", args.debug)
    if not args.jwt and installation_id:
        debug_print(f"Installation ID: {installation_id}", args.debug)
    debug_print(f"PEM path: {pem_path_str}", args.debug)
    debug_print(f"API URL: {args.api_url}", args.debug)
    debug_print(f"User-Agent: {args.user_agent}", args.debug)


def generate_and_output_jwt(args: argparse.Namespace, client_id: str, pem_path: Path) -> None:
    """Generate and output JWT, then exit."""
    jwt_token, issued_at, expires_at = generate_jwt(
        client_id=client_id,
        pem_path=pem_path,
        expiry_seconds=args.jwt_expiry,
        debug=args.debug
    )

    if args.debug:
        debug_print("Successfully generated JWT!", args.debug)
        debug_print(f"JWT: {mask_token(jwt_token)}", args.debug)
        eprint()
    elif not args.quiet:
        eprint(f"Generating JWT (expires in {args.jwt_expiry} seconds)...")
        eprint("Successfully generated JWT!\n")

    output_jwt(jwt_token, issued_at, expires_at, args.output_format, args.quiet)
    sys.exit(0)


def generate_and_output_installation_token(args: argparse.Namespace, client_id: str, pem_path: Path, installation_id: str) -> None:
    """Generate installation token and output it."""
    # Show progress messages
    if not args.quiet and not args.debug:
        eprint(f"Generating JWT (expires in {args.jwt_expiry} seconds)...")
        eprint("Exchanging JWT for installation token...")

    # Get installation token
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

    # Show success information
    show_token_success_info(args, token_data)

    # Output token
    output_installation_token(args, token_data)


def show_token_success_info(args: argparse.Namespace, token_data: Dict[str, Any]) -> None:
    """Show success information after obtaining token."""
    if args.debug:
        debug_print("Successfully obtained installation token!", args.debug)
        debug_print(f"Token: {mask_token(token_data.get('token', ''))}", args.debug)

        expires_at_str = token_data.get('expires_at', '')
        if expires_at_str:
            debug_print(f"Expires at: {expires_at_str}", args.debug)

        permissions_dict = token_data.get('permissions', {})
        if permissions_dict:
            eprint("\n[DEBUG] Permissions granted:")
            eprint(format_permissions(permissions_dict))

        repo_selection = token_data.get('repository_selection', '')
        if repo_selection:
            debug_print(f"Repository selection: {repo_selection}", args.debug)

        eprint()
    elif not args.quiet:
        eprint("Successfully obtained installation token!\n")


def output_installation_token(args: argparse.Namespace, token_data: Dict[str, Any]) -> None:
    """Output the installation token in the requested format."""
    if args.quiet:
        output_token(token_data, args.output_format, True, args.timestamp_format)
    else:
        if args.output_format == 'text':
            print(f"Token: {token_data.get('token', '')}\n")
            expires_at = token_data.get('expires_at', '')
            if expires_at:
                formatted_exp = format_expiration(expires_at, args.timestamp_format)
                print(f"Expires: {formatted_exp}")
        else:
            output_token(token_data, args.output_format, False, args.timestamp_format)


def generate_token(args: argparse.Namespace, client_id: str, pem_path: Path, installation_id: Optional[str]) -> None:
    """Generate either JWT or installation token based on mode."""
    if args.jwt:
        generate_and_output_jwt(args, client_id, pem_path)
    else:
        assert installation_id is not None
        generate_and_output_installation_token(args, client_id, pem_path, installation_id)


def main() -> None:
    """Main entry point - orchestrates token generation workflow."""
    args = parse_arguments()
    validate_command_line_args(args)
    client_id, pem_path, pem_path_str, installation_id = collect_inputs(args)
    show_progress_and_debug_info(args, client_id, pem_path_str, installation_id)
    generate_token(args, client_id, pem_path, installation_id)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        eprint("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        fatal_error(f"Unexpected error: {e}")
