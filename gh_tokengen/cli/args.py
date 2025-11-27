import argparse
from pathlib import Path
from typing import List, Optional
from gh_tokengen.utils import (
    DEFAULT_API_URL,
    DEFAULT_JWT_EXPIRY,
    MAX_JWT_EXPIRY,
    DEFAULT_USER_AGENT,
    __version__,
    ValidationError,
    fatal_error
)
from gh_tokengen.validation import (
    validate_client_id,
    validate_pem_file,
    validate_installation_id,
    validate_jwt_expiry,
    validate_api_url
)

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
        '--show-me-the-curl',
        action='store_true',
        help='Output the equivalent curl command instead of making the API call'
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

    if args.show_me_the_curl and args.jwt:
        parser.error("--show-me-the-curl and --jwt are mutually exclusive")

    if args.show_me_the_curl and not args.installation_id:
        parser.error("--show-me-the-curl requires --installation-id")

    return args
def validate_command_line_args(args: argparse.Namespace) -> None:
    """Validate command-line arguments."""
    try:
        validate_jwt_expiry(args.jwt_expiry)
        validate_api_url(args.api_url)
    except ValidationError as e:
        fatal_error(str(e))

