import sys
from pathlib import Path
from typing import Dict, cast
from gh_tokengen.utils import eprint
from gh_tokengen.output import format_headers_for_display, TokenData
from gh_tokengen.jwt_gen import generate_jwt
from gh_tokengen.http import make_api_request


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
) -> TokenData:
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
    data: Dict[str, object]
    response_headers: Dict[str, str]
    data, response_headers = make_api_request(
        endpoint,
        jwt_token,
        user_agent,
        debug,
        show_headers
    )
    token_data = cast(TokenData, data)

    return token_data

