#!/usr/bin/env python3
"""
gh-tokengen - an UNOFFICIAL GitHub App Authentication Token Generator

Generates installation tokens for GitHub Apps by creating a JWT from a private key
and exchanging it with the GitHub API.

NOTE: This program is NOT supported or endorsed by GitHub. Use at own risk.
"""

import sys
from gh_tokengen.cli.main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
