"""Download and install the cicd-gate Go binary.

Detects platform, downloads from GitHub Releases, and installs to PATH.
"""

import os
import sys
import stat
import platform
import urllib.request
import urllib.error
import shutil
import tempfile
import time

# Map Python platform to GitHub Release asset name
REPO = "monch1962/compliance-platform"
VERSION = "v0.3.3"

PLATFORM_MAP = {
    ("linux", "x86_64"):   "cicd-gate_linux_amd64",
    ("linux", "aarch64"):  "cicd-gate_linux_arm64",
    ("linux", "arm64"):    "cicd-gate_linux_arm64",
    ("darwin", "x86_64"):  "cicd-gate_darwin_amd64",
    ("darwin", "arm64"):   "cicd-gate_darwin_arm64",
}

DOWNLOAD_TIMEOUT = 120  # seconds


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


def _download_file(url, dest):
    """Download a file with timeout support."""
    import ssl
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={
        "User-Agent": "cicd-gate-installer/0.3.3",
        "Accept": "application/octet-stream",
    })
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT, context=ctx) as response:
        with open(dest, "wb") as f:
            chunk_size = 8192
            downloaded = 0
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
    return downloaded


def install_binary(target_dir=None):
    """Download the cicd-gate binary and install it."""
    if target_dir is None:
        target_dir = os.path.join(sys.prefix, "bin")

    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, "cicd-gate")

    asset_name = _get_asset_name()
    url = _download_url(asset_name)

    print(f"Downloading cicd-gate {VERSION} for {platform.platform()}...", flush=True)
    print(f"  URL: {url}", flush=True)

    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp.close()
        size = _download_file(url, tmp.name)
        os.chmod(tmp.name, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        shutil.move(tmp.name, target_path)
        print(f"  Downloaded {size / 1024 / 1024:.1f}MB", flush=True)
    except Exception as e:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
        raise RuntimeError(f"Failed to download cicd-gate: {e}")

    print(f"Installed to {target_path}", flush=True)
    print(f"Run 'cicd-gate version' to verify.", flush=True)
    return target_path


if __name__ == "__main__":
    install_binary()
