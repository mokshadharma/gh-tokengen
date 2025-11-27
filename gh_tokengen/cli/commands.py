import sys
import argparse
from typing import Optional, Dict, Any
from pathlib import Path
from gh_tokengen.utils import eprint, debug_print
from gh_tokengen.output import (
    mask_token,
    output_jwt,
    output_token,
    format_expiration,
    format_permissions
)
from gh_tokengen.jwt_gen import generate_jwt
from gh_tokengen.github import get_installation_token
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

        expires_at_str: str = token_data.get('expires_at', '')
        if expires_at_str:
            debug_print(f"Expires at: {expires_at_str}", args.debug)

        permissions_dict: Dict[str, str] = token_data.get('permissions', {})
        if permissions_dict:
            eprint("\n[DEBUG] Permissions granted:")
            eprint(format_permissions(permissions_dict))

        repo_selection: str = token_data.get('repository_selection', '')
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
            expires_at: str = token_data.get('expires_at', '')
            if expires_at:
                formatted_exp: str = format_expiration(expires_at, args.timestamp_format)
                print(f"Expires: {formatted_exp}")
        else:
            output_token(token_data, args.output_format, False, args.timestamp_format)


def output_curl_command(args: argparse.Namespace, client_id: str, pem_path: Path, installation_id: str) -> None:
    """Generate JWT and output the equivalent curl command."""
    jwt_token: str
    jwt_token, _, _ = generate_jwt(
        client_id=client_id,
        pem_path=pem_path,
        expiry_seconds=args.jwt_expiry,
        debug=False
    )

    api_url: str = args.api_url.rstrip('/')
    endpoint: str = f"{api_url}/app/installations/{installation_id}/access_tokens"

    curl_command: str = f'curl -i -L -X POST -H "Authorization: Bearer {jwt_token}" -H "Accept: application/vnd.github+json" {endpoint}'
    print(curl_command)
    sys.exit(0)


def generate_token(args: argparse.Namespace, client_id: str, pem_path: Path, installation_id: Optional[str]) -> None:
    """Generate either JWT or installation token based on mode."""
    if args.show_me_the_curl:
        assert installation_id is not None
        output_curl_command(args, client_id, pem_path, installation_id)
    elif args.jwt:
        generate_and_output_jwt(args, client_id, pem_path)
    else:
        assert installation_id is not None
        generate_and_output_installation_token(args, client_id, pem_path, installation_id)

