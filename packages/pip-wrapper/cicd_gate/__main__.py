"""Allow python -m cicd_gate to work."""
import sys
import subprocess
import os
from ._install import install_binary


def main():
    # First ensure the binary is installed
    bin_dir = os.path.join(sys.prefix, "bin")
    binary = os.path.join(bin_dir, "cicd-gate")
    
    if not os.path.exists(binary):
        install_binary(bin_dir)
    
    # Run cicd-gate with the same args
    os.execv(binary, [binary] + sys.argv[1:])


if __name__ == "__main__":
    main()
