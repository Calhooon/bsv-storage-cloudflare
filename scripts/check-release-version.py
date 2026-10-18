#!/usr/bin/env python3
"""Refuse a tag unless it equals the package version in Cargo.toml and Cargo.lock."""
import os
from pathlib import Path
import tomllib

package = tomllib.loads(Path("Cargo.toml").read_text())["package"]
assert package["name"] == "bsv-storage-cloudflare", package["name"]
version = package["version"]
locked = [
    entry["version"]
    for entry in tomllib.loads(Path("Cargo.lock").read_text())["package"]
    if entry["name"] == "bsv-storage-cloudflare"
]
assert locked == [version], f"Cargo.lock holds {locked}, manifest {version}"
assert os.environ["GITHUB_REF_NAME"] == f"v{version}", "tag must equal package version"
print(f"release version: {version}; manifest, lock and tag agree")
