#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST JSON findings from stdin to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument("--header", action="append", default=[], help="Extra header as 'Key: Value'")
    args = ap.parse_args()

    # Validate URL scheme before attempting any network call.
    if not args.url.startswith(("http://", "https://")):
        sys.stderr.write("error: --url must start with http:// or https://\n")
        return 1

    raw = sys.stdin.read()
    if not raw.strip():
        sys.stderr.write("error: no input received on stdin\n")
        return 1

    # Validate that the payload is well-formed JSON before sending.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write("error: stdin is not valid JSON: %s\n" % exc)
        return 1

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        key = k.strip()
        val = v.strip()
        if not key:
            sys.stderr.write("error: malformed --header value (expected 'Key: Value'): %r\n" % h)
            return 1
        req.add_header(key, val)

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print("posted %d bytes -> %d" % (len(payload), r.status))
        return 0
    except Exception as e:
        sys.stderr.write("webhook error: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
