import json
import tempfile
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Tuple, List
from gh_tokengen.utils import debug_print, eprint, fatal_error
from gh_tokengen.output import format_headers_for_display



def make_api_request(
    url: str,
    token: str,
    user_agent: str,
    debug: bool,
    show_headers: bool
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Make an API request to GitHub using curl.

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

    response_body: str = ""

    # Use TemporaryDirectory for maximum safety - it guarantees:
    # 1. Only files within the created directory can be affected
    # 2. Automatic cleanup on normal exit, exceptions, and context manager exit
    # 3. The directory is created with secure permissions
    with tempfile.TemporaryDirectory(prefix='gh-tokengen-') as temp_dir:
        # Verify the temp directory is where we expect it to be (defense in depth)
        temp_dir_path: Path = Path(temp_dir)
        system_temp: Path = Path(tempfile.gettempdir())
        if not temp_dir_path.is_relative_to(system_temp):
            fatal_error(f"Temp directory {temp_dir} is not within system temp directory {system_temp}")

        # Create file paths within our isolated temp directory
        body_file: Path = temp_dir_path / 'response_body'
        config_file: Path = temp_dir_path / 'curl_config'
        headers_file: Path = temp_dir_path / 'response_headers'

        try:
            # Write curl config file with secure permissions
            config_content: str = f"""silent
show-error
location
request = POST
output = {body_file}
dump-header = {headers_file}
write-out = %{{json}}
fail-with-body
header = "Authorization: Bearer {token}"
header = "Accept: application/vnd.github+json"
header = "User-Agent: {user_agent}"
header = "X-GitHub-Api-Version: 2022-11-28"
url = {url}
"""
            config_file.write_text(config_content)

            # Run curl
            if debug:
                debug_print("Executing curl request...", debug)

            result: subprocess.CompletedProcess[str] = subprocess.run(
                ['curl', '--config', str(config_file)],
                capture_output=True,
                text=True
            )

            # Parse curl's JSON metadata output
            curl_metadata: Dict[str, Any] = {}
            if result.stdout:
                try:
                    curl_metadata = json.loads(result.stdout)
                except json.JSONDecodeError:
                    pass

            # Read response body from temp file
            if body_file.exists():
                response_body = body_file.read_text()

            # Read response headers from temp file
            # When following redirects, this file contains all response header blocks
            # (one for each response in the redirect chain)
            raw_headers: str = ""
            if headers_file.exists():
                raw_headers = headers_file.read_text()

            # Parse the final response headers into a dictionary
            # (for the return value - we need the last block's headers)
            response_headers: Dict[str, str] = {}
            if raw_headers:
                # Split into blocks (separated by blank lines)
                # and parse the last block for the response_headers dict
                blocks: List[str] = raw_headers.strip().split('\r\n\r\n')
                if not blocks or not blocks[-1]:
                    # Try with just \n\n in case of different line endings
                    blocks = raw_headers.strip().split('\n\n')

                if blocks:
                    last_block: str = blocks[-1]
                    for line in last_block.split('\n'):
                        line = line.rstrip('\r')  # Handle \r\n line endings
                        if ':' in line:
                            key: str
                            value: str
                            key, value = line.split(':', 1)
                            response_headers[key.strip()] = value.strip()

            # Extract status code and other info from curl metadata
            http_code: int = curl_metadata.get('http_code', 0)
            effective_url: str = curl_metadata.get('url_effective', url)
            num_redirects: int = curl_metadata.get('num_redirects', 0)

            # Debug output for redirects
            if debug and num_redirects > 0:
                eprint(f"\n[DEBUG] Followed {num_redirects} redirect(s)")
                eprint(f"[DEBUG] Final URL: {effective_url}")

            if debug:
                eprint("\n[DEBUG] Final response:")
                eprint(f"[DEBUG]   Status: {http_code}")
                eprint(f"[DEBUG]   URL: {effective_url}")

            # Check for HTTP errors
            if http_code >= 400 or result.returncode != 0:
                # Display HTTP status
                eprint(f"\nHTTP Error {http_code}")

                # Display all response headers if requested (shows full redirect chain)
                if show_headers or debug:
                    if raw_headers:
                        eprint("\nResponse headers:")
                        eprint(raw_headers.rstrip())

                # Display error body if present
                if response_body:
                    eprint("\nResponse body:")
                    # Try to pretty-print JSON, otherwise display verbatim
                    try:
                        error_data: Dict[str, Any] = json.loads(response_body)
                        eprint(json.dumps(error_data, indent=2))
                    except (json.JSONDecodeError, ValueError):
                        # Not JSON, display verbatim
                        eprint(response_body)
                elif result.stderr:
                    eprint(f"\ncurl error: {result.stderr}")

                # Exit with error status
                sys.exit(1)

            # Success path
            # Display all response headers if requested (shows full redirect chain)
            if show_headers or debug:
                if raw_headers:
                    eprint("\nResponse headers:")
                    eprint(raw_headers.rstrip())

            if debug:
                eprint("\nResponse body:")
                eprint(response_body)
                eprint()
            elif show_headers:
                eprint()

            data: Dict[str, Any] = json.loads(response_body)
            return data, response_headers

        except FileNotFoundError:
            fatal_error("curl is not installed or not found in PATH")
        except json.JSONDecodeError as e:
            if debug:
                eprint(f"[DEBUG] Failed to parse response as JSON: {e}")
                if response_body:
                    eprint(f"[DEBUG] Response body: {response_body}")
            fatal_error(f"Failed to parse API response as JSON: {e}")
        except Exception as e:
            if debug:
                import traceback
                traceback.print_exc()
            fatal_error(f"Unexpected error during API request: {e}")

    # This should never be reached due to fatal_error calls, but satisfies type checker
    fatal_error("Unexpected code path in make_api_request")

