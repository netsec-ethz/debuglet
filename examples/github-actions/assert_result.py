#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Assert retained, complete TCP measurements, not just an exited WASM guest."""
import base64
import json
import math
import sys


def check(result, target, max_ms):
    if not math.isfinite(max_ms) or max_ms < 0:
        raise ValueError("threshold must be a finite nonnegative number")
    if result.get("format") != "debuglet-result" or result.get("version") not in {"1.0", "1.1", "1.2"}:
        raise ValueError("unsupported result format")
    outcome = result["outcome"]
    if outcome["state"] != "RunStateExited" or outcome.get("error") or outcome.get("exit_code") not in (None, 0):
        raise ValueError("guest did not exit successfully")
    if result["output"]["status"]["state"] != "complete":
        raise ValueError("measurement output is incomplete")
    chunks = result["output"]["entries"]
    report = json.loads(b"".join(base64.b64decode(row["output"], validate=True) for row in chunks))
    if report["target"] != target or len(report["samples"]) != 3:
        raise ValueError("wrong target or missing samples")
    for sample in report["samples"]:
        ms = sample["connect_ms"]
        if sample.get("error") or isinstance(ms, bool) or not isinstance(ms, (int, float)) or not math.isfinite(ms) or not 0 <= ms <= max_ms:
            raise ValueError("TCP connection failed or exceeded the threshold")


if __name__ == "__main__":
    try:
        with open(sys.argv[1], encoding="utf-8") as source:
            check(json.load(source), sys.argv[2], float(sys.argv[3]))
    except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
        sys.exit(f"Measurement assertion failed: {error}")
    print("PASS: all three TCP connections met the threshold")
