import time
from pathlib import Path
from typing import Tuple, Dict, Union, TypedDict
from datetime import datetime, timezone
from gh_tokengen.utils import debug_print, eprint, fatal_error

class JWTPayload(TypedDict):
    iat: int
    exp: int
    iss: str

def generate_jwt(
    client_id: str,
    pem_path: Path,
    expiry_seconds: int,
    debug: bool,
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
        payload: JWTPayload = {
            'iat': now - 60,  # Issued at (with 60s clock skew tolerance)
            'exp': now + expiry_seconds,  # Expiration
            'iss': client_id  # Issuer (Client ID)
        }

        token: str = pyjwt.encode(cast(Dict[str, object], payload), private_key, algorithm='RS256')

        if debug:
            exp_time: datetime = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            debug_print("JWT generated successfully", debug)
            debug_print(f"JWT issued at: {datetime.fromtimestamp(payload['iat'], tz=timezone.utc)}", debug)
            debug_print(f"JWT expires at: {exp_time}", debug)
            debug_print(f"JWT: {token}", debug)

        return token, int(payload['iat']), int(payload['exp'])

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

