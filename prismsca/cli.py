"""PrismSCA command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .inventory import scan_project
from .osv import query_osv, summarize_vulns
from .signals import compute_all_signals
from .handoff import generate_handoff, write_handoff


def cmd_inventory(args: argparse.Namespace) -> int:
    inv = scan_project(args.path)
    if args.format == "json":
        print(json.dumps(inv.to_dict(), indent=2))
    else:
        print(f"Project: {inv.project_path}")
        print(f"Packages found: {len(inv.packages)}\n")
        for p in inv.packages:
            direct = "direct" if p.is_direct else "transitive"
            print(f"  {p.ecosystem:6}  {p.name:30} {p.version:15} ({direct})")
    if args.out:
        Path(args.out).write_text(json.dumps(inv.to_dict(), indent=2))
        print(f"\nWrote inventory to {args.out}")
    return 0


def cmd_osv(args: argparse.Namespace) -> int:
    inv = scan_project(args.path)
    results = {}
    print(f"Querying OSV for {len(inv.packages)} packages...\n")
    for p in inv.packages:
        key = f"{p.ecosystem}:{p.name}@{p.version}"
        res = query_osv(p)
        results[key] = res
        summary = summarize_vulns(res)
        if summary["count"]:
            print(f"  {key}: {summary['count']} vulns → {', '.join(summary['ids'][:5])}")
        else:
            print(f"  {key}: clean")
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"\nWrote OSV results to {args.out}")
    return 0


def cmd_signals(args: argparse.Namespace) -> int:
    inv = scan_project(args.path)
    signals = compute_all_signals(inv.packages)
    if args.format == "json":
        print(json.dumps(signals, indent=2))
    else:
        print(f"Behavioral signals for {len(signals)} packages:\n")
        for key, sig in sorted(signals.items(), key=lambda x: -x[1].get("risk_score", 0)):
            score = sig.get("risk_score", 0)
            flags = [k for k, v in sig.items() if v is True and k != "is_direct"]
            print(f"  [{score}] {key}")
            if flags:
                print(f"       flags: {', '.join(flags)}")
    if args.out:
        Path(args.out).write_text(json.dumps(signals, indent=2))
        print(f"\nWrote signals to {args.out}")
    return 0


def cmd_handoff(args: argparse.Namespace) -> int:
    inv = scan_project(args.path)
    signals = compute_all_signals(inv.packages)
    osv_results = {}
    if not args.skip_osv:
        print("Querying OSV for handoff...")
        for p in inv.packages:
            key = f"{p.ecosystem}:{p.name}@{p.version}"
            osv_results[key] = query_osv(p)
    handoff = generate_handoff(inv, signals, osv_results)
    out_path = args.out or "prismsca-handoff.json"
    write_handoff(handoff, out_path)
    print(f"Handoff written to {out_path}")
    print(f"  packages: {handoff['package_count']}")
    high = sum(1 for p in handoff["packages"] if p.get("signals", {}).get("risk_score", 0) >= 3)
    vulns = sum(1 for p in handoff["packages"] if p.get("osv") and p["osv"]["count"] > 0)
    print(f"  high-risk signals: {high}")
    print(f"  packages with OSV findings: {vulns}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="prismsca",
        description="Local-first SCA: inventory, OSV, behavioral signals, PrismRedline handoff",
    )
    parser.add_argument("--version", action="version", version="PrismSCA 0.1.0")

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

    args = parser.parse_args()
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
