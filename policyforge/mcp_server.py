"""POLICYFORGE MCP server — exposes generate_policies() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-policyforge[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-policyforge[mcp]'", file=sys.stderr)
        return 1

    from policyforge.core import Questionnaire, generate_policies

    app = FastMCP("policyforge")

    @app.tool()
    def policyforge_generate(questionnaire_json: str) -> str:
        """Generate security policies from a JSON questionnaire object. Returns JSON."""
        try:
            data = json.loads(questionnaire_json)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": "invalid JSON: %s" % exc})
        if not isinstance(data, dict):
            return json.dumps({"error": "questionnaire must be a JSON object"})
        try:
            q = Questionnaire.from_dict(data)
            docs = generate_policies(q)
            return json.dumps({"policies": [d.to_dict() for d in docs]})
        except ValueError as exc:
            return json.dumps({"error": str(exc)})

    app.run()
    return 0
