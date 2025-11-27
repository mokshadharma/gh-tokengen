import json
from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from gh_tokengen.utils import debug_print

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
            now_utc_human: datetime = datetime.now(timezone.utc)
            delta_time: timedelta = exp_dt - now_utc_human
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

    lines: List[str] = []
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

