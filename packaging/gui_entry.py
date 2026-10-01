"""Entry point for the frozen desktop app (SubnetSleuth.exe)."""
import sys

from subnetsleuth.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
