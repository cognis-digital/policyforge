"""Core policy-generation engine for POLICYFORGE.

The engine maps a short intake questionnaire onto a catalog of security
policies, each tied to concrete controls drawn from common audit frameworks
(SOC 2 Trust Services Criteria, ISO 27001 Annex A, HIPAA Security Rule).
It renders complete Markdown policy text with the company's specifics filled
in, and produces a control-coverage map so you can see exactly which audit
requirements each generated policy satisfies.

No external dependencies; pure standard library.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# --------------------------------------------------------------------------
# Framework -> control catalog. Each control id maps to a human label.
# --------------------------------------------------------------------------
FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "soc2": {
        "CC6.1": "Logical access security controls",
        "CC6.2": "User registration and de-provisioning",
        "CC6.3": "Role-based access authorization",
        "CC6.6": "Boundary protection / encryption in transit",
        "CC6.7": "Data transmission and disposal",
        "CC7.2": "Security event monitoring",
        "CC7.3": "Incident evaluation",
        "CC7.4": "Incident response program",
        "CC1.4": "Workforce competence and background screening",
    },
    "iso27001": {
        "A.5.15": "Access control",
        "A.5.18": "Access rights provisioning/review",
        "A.5.24": "Incident management planning",
        "A.6.3": "Security awareness and training",
        "A.8.5": "Secure authentication",
        "A.8.13": "Information backup",
        "A.8.24": "Use of cryptography",
    },
    "hipaa": {
        "164.308(a)(1)": "Security management process",
        "164.308(a)(5)": "Security awareness and training",
        "164.308(a)(6)": "Security incident procedures",
        "164.310(d)": "Device and media controls",
        "164.312(a)(1)": "Access control",
        "164.312(e)(1)": "Transmission security / encryption",
    },
}

# --------------------------------------------------------------------------
# Policy catalog. Each entry declares which controls it satisfies per
# framework, the body template, and the conditions under which it applies.
# --------------------------------------------------------------------------
POLICY_CATALOG: Dict[str, Dict] = {
    "information_security": {
        "title": "Information Security Policy",
        "controls": {
            "soc2": ["CC6.1"],
            "iso27001": ["A.5.15"],
            "hipaa": ["164.308(a)(1)"],
        },
        "always": True,
        "body": (
            "## Purpose\n"
            "This policy establishes {company}'s overall approach to protecting "
            "the confidentiality, integrity, and availability of information "
            "assets.\n\n"
            "## Scope\n"
            "Applies to all {employees} employees, contractors, and systems "
            "operated by {company}.\n\n"
            "## Policy\n"
            "- Management commits to a documented security program reviewed at "
            "least annually.\n"
            "- The {security_owner} owns this program and reports to leadership.\n"
            "- All personnel must comply with the policies referenced herein.\n"
        ),
    },
    "access_control": {
        "title": "Access Control Policy",
        "controls": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "iso27001": ["A.5.15", "A.5.18", "A.8.5"],
            "hipaa": ["164.312(a)(1)"],
        },
        "always": True,
        "body": (
            "## Purpose\n"
            "Define how access to {company} systems is granted, reviewed, and "
            "revoked.\n\n"
            "## Policy\n"
            "- Access follows least-privilege and is granted by role.\n"
            "- New access requires {security_owner} approval; offboarding revokes "
            "access within 24 hours.\n"
            "- Access rights are reviewed every {access_review_days} days.\n"
            "- Multi-factor authentication is required for all {cloud} accounts.\n"
        ),
    },
    "encryption": {
        "title": "Encryption & Key Management Policy",
        "controls": {
            "soc2": ["CC6.6", "CC6.7"],
            "iso27001": ["A.8.24"],
            "hipaa": ["164.312(e)(1)"],
        },
        "when": lambda q: q.handles_pii or q.handles_phi or bool(q.cloud),
        "body": (
            "## Purpose\n"
            "Protect {company} data in transit and at rest using cryptography.\n\n"
            "## Policy\n"
            "- Data in transit uses TLS 1.2 or higher.\n"
            "- Data at rest is encrypted with AES-256 on {cloud} storage.\n"
            "- Keys are rotated at least annually and never stored in source code.\n"
            "- Sensitive data types in scope: {data_types}.\n"
        ),
    },
    "incident_response": {
        "title": "Incident Response Policy",
        "controls": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "iso27001": ["A.5.24"],
            "hipaa": ["164.308(a)(6)"],
        },
        "always": True,
        "body": (
            "## Purpose\n"
            "Ensure {company} detects, responds to, and learns from security "
            "incidents.\n\n"
            "## Policy\n"
            "- Suspected incidents are reported to {security_owner} immediately.\n"
            "- Incidents are triaged by severity; criticals trigger a response "
            "within 1 hour.\n"
            "- A post-incident review is completed within 5 business days.\n"
            "- Breach notifications follow applicable legal requirements.\n"
        ),
    },
    "security_training": {
        "title": "Security Awareness & Training Policy",
        "controls": {
            "soc2": ["CC1.4"],
            "iso27001": ["A.6.3"],
            "hipaa": ["164.308(a)(5)"],
        },
        "always": True,
        "body": (
            "## Purpose\n"
            "Equip {company} personnel to recognize and prevent security "
            "threats.\n\n"
            "## Policy\n"
            "- All employees complete security training at hire and annually.\n"
            "- Phishing simulations run at least quarterly.\n"
            "- Completion is tracked by the {security_owner}.\n"
        ),
    },
    "data_retention": {
        "title": "Data Retention & Backup Policy",
        "controls": {
            "soc2": ["CC6.7"],
            "iso27001": ["A.8.13"],
            "hipaa": ["164.310(d)"],
        },
        "when": lambda q: q.handles_pii or q.handles_phi,
        "body": (
            "## Purpose\n"
            "Govern how {company} retains, backs up, and disposes of data.\n\n"
            "## Policy\n"
            "- Production data is backed up daily; backups are encrypted.\n"
            "- Backup restores are tested at least annually.\n"
            "- Data is retained for {retention_days} days then securely disposed.\n"
            "- Sensitive data types: {data_types}.\n"
        ),
    },
}


@dataclass
class Questionnaire:
    """Intake answers that drive policy generation."""

    company: str
    frameworks: List[str] = field(default_factory=lambda: ["soc2"])
    employees: int = 10
    cloud: str = "AWS"
    data_types: List[str] = field(default_factory=lambda: ["customer data"])
    handles_pii: bool = True
    handles_phi: bool = False
    security_owner: str = "Security Officer"
    access_review_days: int = 90
    retention_days: int = 365

    def __post_init__(self) -> None:
        if not self.company or not str(self.company).strip():
            raise ValueError("company is required")
        self.frameworks = [f.lower().strip() for f in self.frameworks]
        unknown = [f for f in self.frameworks if f not in FRAMEWORKS]
        if unknown:
            raise ValueError(
                "unknown framework(s): %s; valid: %s"
                % (", ".join(unknown), ", ".join(sorted(FRAMEWORKS)))
            )
        if not self.frameworks:
            raise ValueError("at least one framework is required")
        if int(self.employees) < 0:
            raise ValueError("employees must be >= 0")

    @classmethod
    def from_dict(cls, d: Dict) -> "Questionnaire":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        extra = set(d) - known
        if extra:
            raise ValueError("unknown question(s): %s" % ", ".join(sorted(extra)))
        return cls(**d)

    def render_context(self) -> Dict[str, str]:
        return {
            "company": self.company,
            "employees": str(self.employees),
            "cloud": self.cloud,
            "data_types": ", ".join(self.data_types) or "none specified",
            "security_owner": self.security_owner,
            "access_review_days": str(self.access_review_days),
            "retention_days": str(self.retention_days),
        }


@dataclass
class PolicyDocument:
    policy_id: str
    title: str
    markdown: str
    controls: Dict[str, List[str]]

    def to_dict(self) -> Dict:
        return asdict(self)


def _applies(spec: Dict, q: Questionnaire) -> bool:
    if spec.get("always"):
        return True
    cond = spec.get("when")
    return bool(cond(q)) if cond else False


def generate_policies(q: Questionnaire) -> List[PolicyDocument]:
    """Render the applicable policy documents for this questionnaire."""
    ctx = q.render_context()
    today = datetime.date.today().isoformat()
    docs: List[PolicyDocument] = []
    for pid, spec in POLICY_CATALOG.items():
        if not _applies(spec, q):
            continue
        # Controls relevant to the frameworks the company selected.
        controls = {
            fw: spec["controls"][fw]
            for fw in q.frameworks
            if fw in spec["controls"]
        }
        if not controls:
            continue  # policy contributes nothing to chosen frameworks
        header = (
            "# %s\n\n"
            "**Organization:** %s  \n"
            "**Effective date:** %s  \n"
            "**Owner:** %s  \n"
            "**Frameworks:** %s\n\n"
        ) % (
            spec["title"],
            q.company,
            today,
            q.security_owner,
            ", ".join(fw.upper() for fw in controls),
        )
        body = spec["body"].format(**ctx)
        ctrl_lines = []
        for fw, ids in controls.items():
            for cid in ids:
                label = FRAMEWORKS[fw].get(cid, "")
                ctrl_lines.append("- `%s` %s (%s)" % (cid, label, fw.upper()))
        mapping = "\n## Mapped Controls\n" + "\n".join(ctrl_lines) + "\n"
        docs.append(
            PolicyDocument(
                policy_id=pid,
                title=spec["title"],
                markdown=header + body + mapping,
                controls=controls,
            )
        )
    return docs


def coverage_report(q: Questionnaire, docs: Optional[List[PolicyDocument]] = None) -> Dict:
    """Compute control coverage per selected framework.

    Returns covered vs total controls and the list of any gaps.
    """
    if docs is None:
        docs = generate_policies(q)
    result: Dict[str, Dict] = {}
    for fw in q.frameworks:
        all_controls = set(FRAMEWORKS[fw])
        covered: Dict[str, List[str]] = {}
        for doc in docs:
            for cid in doc.controls.get(fw, []):
                covered.setdefault(cid, []).append(doc.policy_id)
        covered_ids = set(covered)
        gaps = sorted(all_controls - covered_ids)
        total = len(all_controls)
        result[fw] = {
            "total_controls": total,
            "covered_controls": len(covered_ids),
            "coverage_pct": round(100.0 * len(covered_ids) / total, 1) if total else 0.0,
            "covered": {cid: covered[cid] for cid in sorted(covered)},
            "gaps": [{"id": cid, "label": FRAMEWORKS[fw][cid]} for cid in gaps],
        }
    return result
