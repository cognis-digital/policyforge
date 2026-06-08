"""POLICYFORGE - Auto-generate security policies from a short questionnaire.

Turns a tiny intake questionnaire (company, frameworks, data types, cloud
posture) into a set of audit-ready security policy documents and a control
coverage map. Standard library only, zero install.
"""
from .core import (
    Questionnaire,
    PolicyDocument,
    generate_policies,
    coverage_report,
    FRAMEWORKS,
    POLICY_CATALOG,
)

TOOL_NAME = "policyforge"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Questionnaire",
    "PolicyDocument",
    "generate_policies",
    "coverage_report",
    "FRAMEWORKS",
    "POLICY_CATALOG",
    "TOOL_NAME",
    "TOOL_VERSION",
]
