# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
import base64
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from assert_result import check


class ResultAssertions(unittest.TestCase):
    def setUp(self):
        report = {"target": "127.0.0.1:8000", "samples": [{"connect_ms": 2.0}] * 3}
        self.result = {"format": "debuglet-result", "version": "1.1", "outcome": {"state": "RunStateExited", "error": "", "exit_code": None},
                       "output": {"status": {"state": "complete"}, "entries": [{"output": base64.b64encode(json.dumps(report).encode()).decode()}]}}

    def test_pass_and_failed_assertion_have_different_process_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text(json.dumps(self.result))
            for threshold, success in [(10, True), (0, False)]:
                completed = subprocess.run([sys.executable, str(Path(__file__).with_name("assert_result.py")), str(path), "127.0.0.1:8000", str(threshold)], capture_output=True)
                self.assertEqual(completed.returncode == 0, success)

    def test_incomplete_failed_or_wrong_target_does_not_pass(self):
        for output_state in ("pending", "truncated", "unknown"):
            result = copy.deepcopy(self.result)
            result["output"]["status"]["state"] = output_state
            with self.assertRaises(ValueError):
                check(result, "127.0.0.1:8000", 10)
        self.result["outcome"]["exit_code"] = 1
        with self.assertRaises(ValueError):
            check(self.result, "127.0.0.1:8000", 10)
        self.result["outcome"]["exit_code"] = 0
        with self.assertRaises(ValueError):
            check(self.result, "127.0.0.2:8000", 10)

    def test_failed_connection_is_rejected_despite_zero_guest_exit(self):
        report = {"target": "127.0.0.1:8000", "samples": [{"connect_ms": 0.1, "error": "connection refused"}] * 3}
        self.result["output"]["entries"][0]["output"] = base64.b64encode(json.dumps(report).encode()).decode()
        with self.assertRaises(ValueError):
            check(self.result, "127.0.0.1:8000", 10)


if __name__ == "__main__":
    unittest.main()
