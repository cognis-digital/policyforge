"""Smoke tests for POLICYFORGE. Standard library only, no network."""
import json
import os
import tempfile
import unittest

from policyforge import (
    TOOL_NAME,
    TOOL_VERSION,
    Questionnaire,
    generate_policies,
    coverage_report,
    FRAMEWORKS,
)
from policyforge.cli import main


class TestCore(unittest.TestCase):
    def _q(self, **kw):
        base = dict(company="TestCo", frameworks=["soc2"])
        base.update(kw)
        return Questionnaire(**base)

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "policyforge")
        self.assertTrue(TOOL_VERSION)

    def test_requires_company(self):
        with self.assertRaises(ValueError):
            Questionnaire(company="")

    def test_unknown_framework_rejected(self):
        with self.assertRaises(ValueError):
            Questionnaire(company="X", frameworks=["pci"])

    def test_always_policies_present(self):
        docs = generate_policies(self._q())
        ids = {d.policy_id for d in docs}
        for required in ("information_security", "access_control", "incident_response"):
            self.assertIn(required, ids)

    def test_conditional_policies(self):
        # No PII/PHI and no cloud -> encryption/retention should not appear.
        docs = generate_policies(self._q(handles_pii=False, handles_phi=False, cloud=""))
        ids = {d.policy_id for d in docs}
        self.assertNotIn("data_retention", ids)
        self.assertNotIn("encryption", ids)
        # With PHI -> they appear.
        docs2 = generate_policies(self._q(handles_phi=True))
        ids2 = {d.policy_id for d in docs2}
        self.assertIn("encryption", ids2)
        self.assertIn("data_retention", ids2)

    def test_company_rendered_in_markdown(self):
        docs = generate_policies(self._q(company="Globex LLC"))
        self.assertTrue(all("Globex LLC" in d.markdown for d in docs))
        # No unformatted placeholders left behind.
        for d in docs:
            self.assertNotIn("{company}", d.markdown)

    def test_coverage_math(self):
        q = self._q(frameworks=["soc2"], handles_pii=True)
        rep = coverage_report(q)
        self.assertIn("soc2", rep)
        info = rep["soc2"]
        self.assertEqual(info["total_controls"], len(FRAMEWORKS["soc2"]))
        self.assertLessEqual(info["covered_controls"], info["total_controls"])
        self.assertGreater(info["covered_controls"], 0)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(
            {"company": "CLI Co", "frameworks": ["soc2", "iso27001"], "handles_phi": True},
            self.tmp,
        )
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_generate_json(self):
        rc = main(["--format", "json", "generate", self.tmp.name])
        self.assertEqual(rc, 0)

    def test_coverage_table(self):
        rc = main(["coverage", self.tmp.name])
        self.assertEqual(rc, 0)

    def test_frameworks(self):
        self.assertEqual(main(["frameworks"]), 0)

    def test_missing_file_nonzero(self):
        rc = main(["generate", "does_not_exist_12345.json"])
        self.assertNotEqual(rc, 0)

    def test_bad_json_nonzero(self):
        bad = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        bad.write("{not valid json")
        bad.close()
        try:
            self.assertNotEqual(main(["generate", bad.name]), 0)
        finally:
            os.unlink(bad.name)


if __name__ == "__main__":
    unittest.main()
