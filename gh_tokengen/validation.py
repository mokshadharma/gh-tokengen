from pathlib import Path
from urllib.parse import urlparse
from gh_tokengen.utils import ValidationError, MIN_JWT_EXPIRY, MAX_JWT_EXPIRY

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
        content: str = pem_path.read_text()
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


