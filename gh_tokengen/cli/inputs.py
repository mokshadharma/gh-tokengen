import sys
import os
import argparse
from typing import Optional, Tuple
from pathlib import Path
from gh_tokengen.utils import fatal_error, expand_path, eprint
from gh_tokengen.validation import validate_client_id, validate_pem_file, validate_installation_id
from gh_tokengen.interactive.prompt import prompt_for_input
from gh_tokengen.cli.args import validate_and_collect_errors
def collect_inputs(args: argparse.Namespace) -> Tuple[str, Path, str, Optional[str]]:
    """Collect inputs either interactively or from command-line arguments.

    Returns:
        Tuple of (client_id, pem_path, pem_path_str, installation_id)
    """
    is_interactive: bool = not args.client_id or not args.pem_path or (not args.jwt and not args.installation_id)

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
    use_path_completion: bool = not no_path_completion
    use_fuzzy: bool = not (no_fuzzy or no_path_completion)

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
