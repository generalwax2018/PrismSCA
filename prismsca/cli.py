"""PrismSCA command-line interface."""

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="prismsca",
        description="Local-first SCA: inventory, OSV, behavioral signals, PrismRedline handoff",
    )
    parser.add_argument("--version", action="version", version="PrismSCA 0.1.0")

    sub = parser.add_subparsers(dest="command")

    # Placeholder subcommands — implemented next
    sub.add_parser("inventory", help="Scan projects and build library inventory")
    sub.add_parser("osv", help="Check inventory against OSV")
    sub.add_parser("signals", help="Compute behavioral risk signals")
    sub.add_parser("handoff", help="Generate PrismRedline handoff package")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    print(f"Command '{args.command}' is not yet implemented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
