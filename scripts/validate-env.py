#!/usr/bin/env python3
import os
import sys

def parse_env_file(filepath):
    """
    Parses a .env file and returns a set of keys.
    Ignores comments and empty lines.
    """
    keys = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Handle keys with export prefix
                if line.startswith('export '):
                    line = line[7:]
                # Split at the first =
                if '=' in line:
                    key = line.split('=', 1)[0].strip()
                    keys.add(key)
    except FileNotFoundError:
        return None
    return keys

def main():
    dist_file = '.env.dist'
    env_file = '.env'

    dist_keys = parse_env_file(dist_file)
    env_keys = parse_env_file(env_file)

    if dist_keys is None:
        print(f"❌ Error: {dist_file} not found.")
        sys.exit(1)

    if env_keys is None:
        print(f"❌ Error: {env_file} not found. Run 'make init' first.")
        sys.exit(1)

    missing_keys = dist_keys - env_keys
    extra_keys = env_keys - dist_keys

    # Filter out internal variables that might be added by start.sh but not in dist
    # (e.g., TRAEFIK_DASHBOARD_AUTH, hashes, etc. if they are not in dist)
    # Actually, usually they ARE in dist as placeholders or we ignore them.
    # But usually extra keys are custom user variables, which is fine to report as "Extra" or "Custom".

    has_errors = False

    print(f"🔍 Validating {env_file} against {dist_file}...")
    print("")

    if missing_keys:
        print("❌ MISSING VARIABLES (Present in .env.dist but missing in .env):")
        for key in sorted(missing_keys):
            print(f"   - {key}")
        print("   👉 Action: Add these variables to your .env file or run 'make init' again.")
        has_errors = True
        print("")

    if extra_keys:
        print("ℹ️  EXTRA VARIABLES (Present in .env but not in .env.dist):")
        for key in sorted(extra_keys):
            print(f"   + {key}")
        print("   (These might be custom variables or generated secrets. Verify they are intended.)")
        print("")

    if not missing_keys:
        print("✅ All required variables from .env.dist are present in .env.")

    if has_errors:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
