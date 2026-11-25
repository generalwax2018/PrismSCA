"""PrismSCA command-line interface.

Exit codes: 0 success, 1 one or more OSV lookups failed, 2 bad path, 130 interrupted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .inventory import SUPPORTED_FILES, ProjectInventory, scan_project
from .osv import query_osv_batch, summarize_vulns
from .signals import HIGH_RISK_THRESHOLD, RISK_FLAGS, compute_all_signals
from .handoff import generate_handoff, write_handoff

PIN_HINT = (
    "Pin them with a lockfile (uv lock, poetry lock, pip-compile / pip freeze, npm install) "
    "to check them against OSV."
)


def _scan(path: str) -> ProjectInventory:
    inv = scan_project(path)
    for w in inv.warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not inv.packages:
        print(f"No dependencies found under {inv.project_path}.\nLooked for: {SUPPORTED_FILES}", file=sys.stderr)
    return inv


def _write_json(path: str, data: object) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def cmd_inventory(args: argparse.Namespace) -> int:
    inv = _scan(args.path)
    if args.format == "json":
        print(json.dumps(inv.to_dict(), indent=2))
    else:
        print(f"Project: {inv.project_path}")
        print(f"Packages found: {len(inv.packages)}\n")
        for p in inv.packages:
            direct = "direct" if p.is_direct else "transitive"
            print(f"  {p.ecosystem:6}  {p.name:30} {p.version:15} ({direct})")
    if args.out:
        _write_json(args.out, inv.to_dict())
        print(f"\nWrote inventory to {args.out}")
    return 0


def cmd_osv(args: argparse.Namespace) -> int:
    inv = _scan(args.path)
    print(f"Querying OSV for {len(inv.packages)} packages...\n")
    results = query_osv_batch(inv.packages)
    errors = 0
    skipped = []
    for p in inv.packages:
        s = summarize_vulns(results.get(p.key))
        if s["status"] == "skipped":
            skipped.append(f"{p.name} {p.version}")
            continue
        if s["status"] == "ok":
            line = f"{s['count']} vulns -> {', '.join(s['ids'][:5])}" if s["count"] else "clean"
        else:
            errors += 1
            line = f"ERROR: {s['detail']}"
        print(f"  {p.key}: {line}")
    if skipped:
        print(f"\n{len(skipped)} package(s) not checked because no single version is pinned: {', '.join(skipped)}")
        print(PIN_HINT)
    if args.out:
        _write_json(args.out, results)
        print(f"\nWrote OSV results to {args.out}")
    if errors:
        print(f"\n{errors} lookup(s) failed; those packages are unchecked, not clean.", file=sys.stderr)
        return 1
    return 0


def cmd_signals(args: argparse.Namespace) -> int:
    inv = _scan(args.path)
    signals = compute_all_signals(inv.packages)
    if args.format == "json":
        print(json.dumps(signals, indent=2))
    else:
        print(f"Behavioral signals for {len(signals)} packages:\n")
        for key, sig in sorted(signals.items(), key=lambda x: -x[1].get("risk_score", 0)):
            flags = [f for f in RISK_FLAGS if sig.get(f)]
            print(f"  [{sig.get('risk_score', 0)}] {key}")
            if flags:
                print(f"       flags: {', '.join(flags)}")
    if args.out:
        _write_json(args.out, signals)
        print(f"\nWrote signals to {args.out}")
    return 0


def cmd_handoff(args: argparse.Namespace) -> int:
    inv = _scan(args.path)
    signals = compute_all_signals(inv.packages)
    osv_results = None
    if not args.skip_osv:
        print("Querying OSV for handoff...")
        osv_results = query_osv_batch(inv.packages)
    handoff = generate_handoff(inv, signals, osv_results)
    write_handoff(handoff, args.out)

    pkgs = handoff["packages"]
    high = sum(1 for p in pkgs if p["signals"].get("risk_score", 0) >= HIGH_RISK_THRESHOLD)
    print(f"Handoff written to {args.out}")
    print(f"  packages: {handoff['package_count']}")
    print(f"  high-risk signals (score >= {HIGH_RISK_THRESHOLD}): {high}")
    if osv_results is None:
        print("  OSV: skipped")
        return 0
    statuses = [p["osv"]["status"] for p in pkgs]
    vulns = sum(1 for p in pkgs if p["osv"]["count"])
    print(f"  packages with OSV findings: {vulns}")
    skipped = statuses.count("skipped")
    print(f"  OSV lookups skipped (unpinned): {skipped}")
    if skipped:
        print(f"  {PIN_HINT}")
    errors = statuses.count("error")
    if errors:
        print(f"  OSV lookups FAILED: {errors} (unchecked, not clean)", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prismsca",
        description="Local-first SCA: inventory, OSV, behavioral signals, PrismRedline handoff",
    )
    parser.add_argument("--version", action="version", version=f"PrismSCA {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    p_inv = sub.add_parser("inventory", help="Scan projects and build library inventory")
    p_inv.add_argument("path", nargs="?", default=".", help="Project path (default: .)")
    p_inv.add_argument("--format", choices=["text", "json"], default="text")
    p_inv.add_argument("--out", help="Write JSON inventory to file")
    p_inv.set_defaults(func=cmd_inventory)

    p_osv = sub.add_parser("osv", help="Check inventory against OSV")
    p_osv.add_argument("path", nargs="?", default=".")
    p_osv.add_argument("--out", help="Write raw OSV results to file")
    p_osv.set_defaults(func=cmd_osv)

    p_sig = sub.add_parser("signals", help="Compute behavioral risk signals")
    p_sig.add_argument("path", nargs="?", default=".")
    p_sig.add_argument("--format", choices=["text", "json"], default="text")
    p_sig.add_argument("--out")
    p_sig.set_defaults(func=cmd_signals)

    p_hand = sub.add_parser("handoff", help="Generate PrismRedline handoff package")
    p_hand.add_argument("path", nargs="?", default=".")
    p_hand.add_argument("--out", default="prismsca-handoff.json")
    p_hand.add_argument("--skip-osv", action="store_true", help="Skip OSV queries (faster, local-only)")
    p_hand.set_defaults(func=cmd_handoff)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
