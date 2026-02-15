#!/usr/bin/env python3
import os
import sys
import argparse
import shutil

def parse_env_file_keys(filepath):
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

def get_env_values(filepath):
    """
    Returns a dictionary of key-value pairs from a .env file.
    """
    values = {}
    if not os.path.exists(filepath):
        return values
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:]
            if '=' in line:
                parts = line.split('=', 1)
                key = parts[0].strip()
                value = parts[1]
                values[key] = value
    return values

def sync_env(dist_file, env_file):
    """
    Synchronizes .env with .env.dist.
    - Adds missing variables from .env.dist (with default values).
    - Removes extra variables from .env that are not in .env.dist.
    - Preserves .env.dist structure and comments.
    """
    if not os.path.exists(dist_file):
        print(f"❌ Error: {dist_file} not found.")
        return False

    current_values = get_env_values(env_file)
    
    # Create a backup
    if os.path.exists(env_file):
        shutil.copy(env_file, f"{env_file}.bak")
        print(f"📦 Backup created at {env_file}.bak")

    new_lines = []
    with open(dist_file, 'r') as f:
        for line in f:
            # Preserve empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                new_lines.append(line)
                continue

            # Check if it's a variable definition
            original_line = line
            if stripped.startswith('export '):
                stripped = stripped[7:]

            if '=' in stripped:
                key = stripped.split('=', 1)[0].strip()
                if key in current_values:
                    # Use existing value
                    # Check if original was exported
                    prefix = "export " if original_line.strip().startswith('export ') else ""
                    new_lines.append(f"{prefix}{key}={current_values[key]}\n")
                else:
                    # Keep .env.dist default
                    new_lines.append(line)
                    print(f"➕ Added missing variable: {key}")
            else:
                new_lines.append(line)

    with open(env_file, 'w') as f:
        f.writelines(new_lines)

    return True

def main():
    parser = argparse.ArgumentParser(description="Validate and sync .env against .env.dist")
    parser.add_argument("--sync", action="store_true", help="Synchronize .env with .env.dist (adds missing, removes extra)")
    args = parser.parse_args()

    dist_file = '.env.dist'
    env_file = '.env'

    if args.sync:
        print(f"🔄 Synchronizing {env_file} with {dist_file}...")
        if sync_env(dist_file, env_file):
            print("✅ Environment synchronized successfully.")
            # Verify after sync
            dist_keys = parse_env_file_keys(dist_file)
            env_keys = parse_env_file_keys(env_file)
            extra_keys = env_keys - dist_keys
            if extra_keys:
                # This shouldn't happen with the current sync logic
                print(f"⚠️ Warning: Found unexpected extra keys after sync: {', '.join(extra_keys)}")
        else:
            sys.exit(1)
        return

    dist_keys = parse_env_file_keys(dist_file)
    env_keys = parse_env_file_keys(env_file)

    if dist_keys is None:
        print(f"❌ Error: {dist_file} not found.")
        sys.exit(1)

    if env_keys is None:
        print(f"❌ Error: {env_file} not found. Run 'make init' first.")
        sys.exit(1)

    missing_keys = dist_keys - env_keys
    extra_keys = env_keys - dist_keys

    has_errors = False

    print(f"🔍 Validating {env_file} against {dist_file}...")
    print("")

    if missing_keys:
        print("❌ MISSING VARIABLES (Present in .env.dist but missing in .env):")
        for key in sorted(missing_keys):
            print(f"   - {key}")
        print("   👉 Action: Run 'make sync' or add them manually.")
        has_errors = True
        print("")

    if extra_keys:
        print("⚠️  EXTRA VARIABLES (Present in .env but not in .env.dist):")
        for key in sorted(extra_keys):
            print(f"   + {key}")
        print("   👉 Note: These will be removed if you run 'make sync'.")
        print("")

    if not missing_keys and not extra_keys:
        print("✅ All required variables from .env.dist are present in .env and no extras found.")
    elif not missing_keys:
        print("✅ All required variables from .env.dist are present in .env.")

    if has_errors:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
