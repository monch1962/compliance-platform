"""Download and install the cicd-gate Go binary.

Detects platform, downloads from GitHub Releases, and installs to PATH.
"""

import os
import sys
import stat
import platform
import urllib.request
import urllib.error
import json
import shutil
import subprocess
import tempfile

# Map Python platform to GitHub Release asset name
REPO = "monch1962/compliance-platform"
VERSION = "v0.3.1"

PLATFORM_MAP = {
    ("linux", "x86_64"):   "cicd-gate_linux_amd64",
    ("linux", "aarch64"):  "cicd-gate_linux_arm64",
    ("linux", "arm64"):    "cicd-gate_linux_arm64",
    ("darwin", "x86_64"):  "cicd-gate_darwin_amd64",
    ("darwin", "arm64"):   "cicd-gate_darwin_arm64",
}


def _get_asset_name():
    system = platform.system().lower()
    machine = platform.machine().lower()
    key = (system, machine)
    if key not in PLATFORM_MAP:
        supported = "\n".join(f"  {s}/{m}" for s, m in PLATFORM_MAP)
        raise RuntimeError(
            f"Unsupported platform: {system}/{machine}\n"
            f"Supported platforms:\n{supported}"
        )
    return PLATFORM_MAP[key]


def _download_url(asset_name):
    return (
        f"https://github.com/{REPO}/releases/download/{VERSION}/{asset_name}"
    )


def install_binary(target_dir=None):
    """Download the cicd-gate binary and install it."""
    if target_dir is None:
        # Install to Python's bin directory (on PATH after pip install)
        target_dir = os.path.join(sys.prefix, "bin")
    
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, "cicd-gate")
    
    asset_name = _get_asset_name()
    url = _download_url(asset_name)
    
    print(f"Downloading cicd-gate {VERSION} for {platform.platform()}...")
    print(f"  URL: {url}")
    
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            urllib.request.urlretrieve(url, tmp.name)
            os.chmod(tmp.name, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            shutil.move(tmp.name, target_path)
    except Exception as e:
        raise RuntimeError(f"Failed to download cicd-gate: {e}")
    
    print(f"Installed to {target_path}")
    print(f"Run 'cicd-gate version' to verify.")
    return target_path


if __name__ == "__main__":
    install_binary()
