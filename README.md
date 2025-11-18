# gh-tokengen

**An UNOFFICIAL GitHub App Authentication Token Generator**

> This program is **NOT supported or endorsed by GitHub**. Use at your own risk.

## Overview

`gh-tokengen` is a command-line utility that generates authentication tokens for GitHub Apps. It creates JSON Web Tokens (JWTs) from a GitHub App's private key and can optionally exchange them with the GitHub API to obtain installation access tokens.

This tool is useful for developers and system administrators who need to programmatically authenticate as a GitHub App to access repositories, perform automated actions, or integrate with GitHub's API.

## Features

- **JWT Generation**: Create JSON Web Tokens signed with your GitHub App's private key
- **Installation Token Exchange**: Automatically exchange JWTs for installation access tokens
- **Multiple Output Formats**: Output tokens as plain text, JSON, environment variables, or HTTP headers
- **Interactive Mode**: Prompts for required inputs if not provided via command-line arguments
- **Input Validation**: Validates Client IDs, Installation IDs, and PEM file formats
- **Debug Mode**: Detailed logging of JWT generation and API requests (with token masking for security)
- **Dry Run**: Test your configuration without making actual API calls
- **GitHub Enterprise Support**: Works with custom GitHub Enterprise API URLs
- **Flexible Token Expiry**: Configure JWT expiration time (1-600 seconds)

## Requirements

### Dependencies

- Python 3.14 or higher
- `PyJWT` library
- `cryptography` library

### Installation

The tool includes a wrapper script that automatically manages the Python virtual environment. No manual activation is required.

**Using uv (recommended):**
```bash
uv venv
uv pip install -e .
```

**Using standard Python:**
```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Once installed, the `gh-tokengen` script can be run directly and will automatically use the correct virtual environment. You can also create a symlink to make it available system-wide:

```bash
# Example: symlink to a directory in your PATH
ln -s /path/to/gh-tokengen/gh-tokengen ~/bin/gh-tokengen
# or
ln -s /path/to/gh-tokengen/gh-tokengen /usr/local/bin/gh-tokengen
```

The script will work correctly even when run via symlink from any location.

### GitHub App Requirements

To use this tool, you need:

1. **GitHub App Client ID**: Found in your GitHub App settings (format: `Iv1.xxxxxxxxxx`)
2. **Private Key File**: A PEM file generated from your GitHub App settings
3. **Installation ID**: The numeric ID of the GitHub App installation (only required for installation tokens)

## Usage

### Basic Syntax

```bash
./gh-tokengen [OPTIONS]
```

### Common Use Cases

#### 1. Interactive Mode (Recommended for First-Time Users)

Simply run the program and it will prompt you for all required inputs:

```bash
./gh-tokengen
```

#### 2. Generate Installation Token

Provide all arguments on the command line:

```bash
./gh-tokengen \
  --client-id Iv1.abc123def456 \
  --pem-path ~/.ssh/my-github-app.pem \
  --installation-id 12345678
```

#### 3. Generate JWT Only (No API Call)

Use the `--jwt` flag to generate only the JWT without exchanging it for an installation token:

```bash
./gh-tokengen \
  --jwt \
  --client-id Iv1.abc123def456 \
  --pem-path ~/.ssh/my-github-app.pem
```

> **Note**: The `--jwt` and `--installation-id` options are mutually exclusive.

#### 4. Output as Environment Variable

Perfect for sourcing in shell scripts:

```bash
eval $(./gh-tokengen \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --installation-id 12345678 \
  --output-format env \
  --quiet)

# Now $GITHUB_TOKEN is available
echo $GITHUB_TOKEN
```

#### 5. Output as JSON

Useful for parsing in scripts or applications:

```bash
./gh-tokengen \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --installation-id 12345678 \
  --output-format json
```

Output example:
```json
{
  "token": "ghs_1234567890abcdefghijklmnopqrstuvwxyz",
  "expires_at": "2025-11-14T12:00:00+00:00",
  "permissions": {
    "contents": "read",
    "metadata": "read"
  },
  "repository_selection": "all",
  "expires_in_seconds": 3600
}
```

#### 6. JWT Output as JSON

Generate a JWT with detailed timestamp information:

```bash
./gh-tokengen \
  --jwt \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --output-format json
```

Output example:
```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "issued_at": "2025-11-14T11:00:00+00:00",
  "expires_at": "2025-11-14T11:10:00+00:00"
}
```

#### 7. Debug Mode

See detailed information about the token generation process:

```bash
./gh-tokengen \
  --debug \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --installation-id 12345678
```

#### 8. Quiet Mode

Output only the token (useful for piping to other commands):

```bash
TOKEN=$(./gh-tokengen \
  --quiet \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --installation-id 12345678)

curl -H "Authorization: Bearer $TOKEN" https://api.github.com/app
```

#### 9. Dry Run

Test your configuration without making actual API calls:

```bash
./gh-tokengen \
  --dry-run \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --installation-id 12345678
```

#### 10. GitHub Enterprise

Use with GitHub Enterprise Server:

```bash
./gh-tokengen \
  --api-url https://github.company.com/api/v3 \
  --client-id Iv1.abc123def456 \
  --pem-path app.pem \
  --installation-id 12345678
```

## Command-Line Options

### Required Inputs

| Option | Description |
|--------|-------------|
| `--client-id` | GitHub App Client ID (format: `Iv1.xxxxxxxxxx`) |
| `--pem-path` | Path to the private key PEM file |
| `--installation-id` | Installation ID (required unless using `--jwt`) |

> **Note**: If not provided via command-line, the program will prompt for these interactively.

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--api-url` | `https://api.github.com` | GitHub API base URL |
| `--jwt-expiry` | `600` | JWT expiry time in seconds (1-600) |
| `--user-agent` | `GitHubAppAuth-Script/1.0.0` | Custom User-Agent header |

### Output Options

| Option | Values | Description |
|--------|--------|-------------|
| `--output-format` | `text`, `json`, `env`, `header` | Output format (default: `text`) |
| `--timestamp-format` | `human`, `iso8601`, `relative`, `unix` | Timestamp format (default: `human`) |

### Mode Options

| Option | Description |
|--------|-------------|
| `--jwt` | Generate only JWT, don't exchange for installation token |
| `--debug` | Enable verbose debug output |
| `--quiet` | Suppress all output except the token |
| `--dry-run` | Validate inputs without making API calls |
| `--headers` | Show HTTP response headers |
| `--force` | Skip input validation checks |

### Other Options

| Option | Description |
|--------|-------------|
| `--version` | Show version information |
| `--help`, `-h` | Show help message |

## Output Formats

### Text (Default)

Plain token output:
```
ghs_1234567890abcdefghijklmnopqrstuvwxyz
```

With additional info (non-quiet mode):
```
Token: ghs_1234567890abcdefghijklmnopqrstuvwxyz

Expires: in 60 minutes (2025-11-14 12:00:00 UTC)
```

### JSON

Structured data perfect for parsing:
```json
{
  "token": "ghs_1234567890abcdefghijklmnopqrstuvwxyz",
  "expires_at": "2025-11-14T12:00:00Z",
  "permissions": {
    "contents": "read",
    "metadata": "read"
  },
  "repository_selection": "all",
  "expires_in_seconds": 3600
}
```

### Environment Variable

Ready to source in shell scripts:
```bash
export GITHUB_TOKEN=ghs_1234567890abcdefghijklmnopqrstuvwxyz
```

### HTTP Header

Ready to use in HTTP requests:
```
Authorization: Bearer ghs_1234567890abcdefghijklmnopqrstuvwxyz
```

## How It Works

### JWT Generation Mode (`--jwt`)

1. Reads your GitHub App's private key from the PEM file
2. Creates a JWT with:
   - `iss` (issuer): Your Client ID
   - `iat` (issued at): Current time minus 60 seconds (for clock skew)
   - `exp` (expiration): Current time plus expiry seconds (default 600)
3. Signs the JWT using RS256 algorithm
4. Outputs the JWT in your chosen format

### Installation Token Mode (Default)

1. Generates a JWT (as above)
2. Makes a POST request to GitHub's API:
   ```
   POST /app/installations/{installation_id}/access_tokens
   Authorization: Bearer {jwt}
   ```
3. Receives an installation access token with:
   - The token string
   - Expiration time (typically 1 hour)
   - Granted permissions
   - Repository access scope
4. Outputs the installation token in your chosen format

## Security Considerations

**IMPORTANT SECURITY NOTES**:

1. **Private Key Protection**: Your PEM file contains sensitive cryptographic material. Protect it with appropriate file permissions (e.g., `chmod 600 app.pem`)

2. **Token Handling**: Installation tokens grant access to repositories. Never commit them to version control or log them in plain text.

3. **Token Expiration**: Installation tokens typically expire after 1 hour. JWTs expire based on your `--jwt-expiry` setting (default 10 minutes).

4. **Debug Mode**: When using `--debug`, tokens are partially masked in output, but exercise caution in shared environments.

5. **Quiet Mode**: Use `--quiet` when you need just the token, but be aware this makes the output more sensitive.

## Troubleshooting

### "Virtual environment not found"

If you see an error about a missing virtual environment, ensure you've run the installation steps:
```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

The virtual environment must be created in the same directory as the `gh-tokengen` script.

### "PEM file not found"

Ensure the path to your PEM file is correct. You can use absolute paths or `~` for home directory:
```bash
--pem-path ~/path/to/your-app.pem
```

### "Client ID should start with 'Iv1.'"

GitHub App Client IDs have a specific format. Make sure you're using the Client ID, not the App ID. Find it in your GitHub App settings under "General" → "Client ID".

### "Installation ID must be numeric"

The Installation ID is a number you can find in the URL when viewing your app's installation or via the API. It should be just digits, e.g., `12345678`.

### "Required dependencies not found"

Install the required Python packages:
```bash
pip install PyJWT cryptography
```

### "HTTP 401 error"

This usually means:
- Your Client ID is incorrect
- Your PEM file doesn't match the GitHub App
- The JWT has expired (increase `--jwt-expiry` if needed)

### "HTTP 404 error"

This usually means:
- The Installation ID is incorrect or doesn't exist
- The API URL is wrong (check if you need `--api-url` for GitHub Enterprise)

## Finding Your GitHub App Credentials

### Client ID

1. Go to your GitHub App settings: `Settings` → `Developer settings` → `GitHub Apps`
2. Click on your app name
3. Look for "Client ID" in the "General" section (format: `Iv1.xxxxxxxxxx`)

### Private Key

1. In your GitHub App settings (same location as above)
2. Scroll to "Private keys" section
3. Click "Generate a private key"
4. Save the downloaded `.pem` file securely

### Installation ID

**Method 1**: From the installation URL
1. Install your app on a repository or organization
2. Visit the installation page
3. The URL will be: `https://github.com/settings/installations/12345678`
4. The number at the end is your Installation ID

**Method 2**: Via API
```bash
curl -H "Authorization: Bearer YOUR_JWT" \
  https://api.github.com/app/installations
```

## Use Cases

### CI/CD Pipelines

Generate installation tokens for GitHub Actions or other CI/CD systems:

```bash
# In your CI script
TOKEN=$(./gh-tokengen \
  --quiet \
  --client-id "$GH_APP_CLIENT_ID" \
  --pem-path "$GH_APP_PEM_PATH" \
  --installation-id "$GH_APP_INSTALLATION_ID")

# Use the token
git clone https://x-access-token:$TOKEN@github.com/org/repo.git
```

### Automated Repository Access

Access private repositories in automation scripts:

```bash
eval $(./gh-tokengen \
  --output-format env \
  --quiet \
  --client-id Iv1.abc123 \
  --pem-path app.pem \
  --installation-id 12345678)

# Use GitHub API with the token
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/owner/repo/contents/file.txt
```

### Token Refresh Scripts

Create a wrapper script that automatically refreshes tokens:

```bash
#!/bin/bash
# refresh-token.sh

gh-tokengen \
  --quiet \
  --output-format env \
  --client-id "$CLIENT_ID" \
  --pem-path "$PEM_PATH" \
  --installation-id "$INSTALL_ID" > /tmp/github-token.env

source /tmp/github-token.env
rm /tmp/github-token.env

# Now $GITHUB_TOKEN is available
```

### Testing and Development

Use `--dry-run` and `--debug` to test your configuration:

```bash
./gh-tokengen \
  --dry-run \
  --debug \
  --client-id Iv1.abc123 \
  --pem-path app.pem \
  --installation-id 12345678
```

## More information

- [Authenticating with a GitHub App](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/authenticating-with-a-github-app)
- [GitHub App Installation Token and Authenticating as a GitHub App #48186](https://github.com/orgs/community/discussions/48186)

## License

See the LICENSE file for details.

## Disclaimer

**This tool is provided "as is", without warranty of any kind, express or implied. This is an unofficial tool and is NOT supported or endorsed by GitHub, Inc. Use at your own risk.**

The authors and contributors of this tool:
- Make no warranties about its correctness, reliability, or security
- Are not responsible for any damages or issues arising from its use
- Recommend following GitHub's official documentation for production use
- Suggest reviewing GitHub's official SDKs and tools as alternatives

## Support

- Open an issue in this repository.
- GitHub is **not** responsible for support of this program.

## Version

Current version: 1.0.0

---

**Remember**: Always follow GitHub's Terms of Service and API usage guidelines when using this tool.
