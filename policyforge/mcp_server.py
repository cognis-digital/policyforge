"""POLICYFORGE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from policyforge.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-policyforge[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-policyforge[mcp]'")
        return 1
    app = FastMCP("policyforge")

    @app.tool()
    def policyforge_scan(target: str) -> str:
        """Auto-generate security policies from a short questionnaire. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
