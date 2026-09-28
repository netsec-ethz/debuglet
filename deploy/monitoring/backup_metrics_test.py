# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Failure and malformed-output regressions for the offline backup wrapper."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("backup_metrics", Path(__file__).with_name("backup-metrics.py"))
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupMetricsTest(unittest.TestCase):
    def test_only_verified_completed_command_advances_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metrics = root / "backup.prom"
            manifest = {"schema_version": 1, "layout": "dispatcher",
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                        "roles": [{"role": "dispatcher", "identity": "fixture", "schema_version": 8}],
                        "files": {"state.db": {"sha256": "b" * 64, "bytes": 10}},
                        "package": {"source_sha": "a" * 40, "version": "v0.0.0-test"}}
            (root / "backup.json").write_text(json.dumps(manifest))
            argv = ["backup-metrics.py", "--dbl", sys.executable, "--state-dir", directory,
                    "--destination", directory, "--metrics-file", str(metrics), "--offline"]
            cases = [subprocess.CalledProcessError(1, "backup"), subprocess.TimeoutExpired("backup", 310),
                     b"not JSON", b"{}", json.dumps(dict(manifest, observed_at=None)).encode(),
                     json.dumps(dict(manifest, roles=[{}])).encode(),
                     json.dumps(dict(manifest, files={"bad": {"sha256": "x", "bytes": 1}})).encode(),
                     json.dumps(dict(manifest, layout="executor")).encode()]
            for result in cases:
                with self.subTest(result=repr(result)):
                    backup.publish(metrics, True, 10, 10)
                    with patch.object(sys, "argv", argv), patch.object(backup.subprocess, "run") as run:
                        if isinstance(result, Exception):
                            run.side_effect = result
                        else:
                            run.return_value = subprocess.CompletedProcess([], 0, result)
                        self.assertEqual(backup.main(), 1)
                    self.assertEqual(backup.last_success(metrics), 10)
                    self.assertIn("debuglet_backup_last_completed_success 0", metrics.read_text())
            with patch.object(sys, "argv", argv), patch.object(backup.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, json.dumps(manifest).encode())
                began = time.time()
                self.assertEqual(backup.main(), 0)
            self.assertGreaterEqual(backup.last_success(metrics), began)
            self.assertIn("debuglet_backup_last_completed_success 1", metrics.read_text())


if __name__ == "__main__":
    unittest.main()
