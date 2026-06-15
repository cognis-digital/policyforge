"""Command-line interface for POLICYFORGE.

Subcommands:
  generate  Read a questionnaire JSON file and emit policy documents.
  coverage  Show control-coverage map for a questionnaire.
  frameworks  List supported frameworks and their controls.

Global flags: --version, --format {table,json}.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    FRAMEWORKS,
    Questionnaire,
    coverage_report,
    generate_policies,
)


def _load_questionnaire(path: str) -> Questionnaire:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("questionnaire must be a JSON object")
    return Questionnaire.from_dict(data)


def _print_table(lines: List[str]) -> None:
    sys.stdout.write("\n".join(lines) + "\n")


def _cmd_generate(args: argparse.Namespace) -> int:
    q = _load_questionnaire(args.input)
    docs = generate_policies(q)
    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "company": q.company,
            "policies": [d.to_dict() for d in docs],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        lines = ["Generated %d policies for %s:" % (len(docs), q.company), ""]
        for d in docs:
            ctrl_count = sum(len(v) for v in d.controls.values())
            lines.append("  - %-38s (%d controls)" % (d.title, ctrl_count))
        _print_table(lines)
    return 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    q = _load_questionnaire(args.input)
    report = coverage_report(q)
    if args.format == "json":
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        lines = ["Control coverage for %s:" % q.company, ""]
        for fw, info in report.items():
            lines.append(
                "  %-10s %d/%d controls (%.1f%%)"
                % (fw.upper(), info["covered_controls"], info["total_controls"], info["coverage_pct"])
            )
            for gap in info["gaps"]:
                lines.append("      GAP %s %s" % (gap["id"], gap["label"]))
        _print_table(lines)
    return 0


def _cmd_frameworks(args: argparse.Namespace) -> int:
    if args.format == "json":
        sys.stdout.write(json.dumps(FRAMEWORKS, indent=2) + "\n")
    else:
        lines = []
        for fw, controls in FRAMEWORKS.items():
            lines.append("%s (%d controls)" % (fw.upper(), len(controls)))
            for cid, label in controls.items():
                lines.append("  %-16s %s" % (cid, label))
        _print_table(lines)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Auto-generate audit-ready security policies from a questionnaire.",
    )
    p.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    p.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="output format (default: table)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate policy documents")
    g.add_argument("input", help="path to questionnaire JSON file")
    g.set_defaults(func=_cmd_generate)

    c = sub.add_parser("coverage", help="show control coverage map")
    c.add_argument("input", help="path to questionnaire JSON file")
    c.set_defaults(func=_cmd_coverage)

    f = sub.add_parser("frameworks", help="list supported frameworks/controls")
    f.set_defaults(func=_cmd_frameworks)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        path = e.filename or str(e)
        sys.stderr.write("error: file not found: %s\n" % path)
        return 2
    except PermissionError as e:
        path = e.filename or str(e)
        sys.stderr.write("error: permission denied: %s\n" % path)
        return 2
    except (ValueError, json.JSONDecodeError) as e:
        sys.stderr.write("error: %s\n" % e)
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
