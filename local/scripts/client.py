#!/usr/bin/env python3
# Copyright 2025 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""client.py — submit one TEST debuglet and follow its stored output.

Talks to the dispatcher HTTP API as implemented in
internal/dispatcher/transport/api (routes.go / handlers_debuglet.go):

  GET  {base}/executors          -> [ {id, ready, last_seen, ...} ]
  PUT  {base}/payment/intent     <- payment request
  PUT  {base}/debuglet           <- authenticated submission
  GET  {base}/debuglet/<id>/logs -> paginated output and run state

Note: in the current `dev` checkout the routes are registered at the root
(routes.go), so the executor list is at /executors. If your branch mounts the
API under a group (e.g. /api), pass --base-path /api.

The local dispatcher runs with disable_tls=true (plain HTTP on :9000), so TLS
is OFF by default; pass --tls to use https.

To drive a two-debuglet test (e.g. latency_tcp_server + latency_tcp), run this
script twice: once for the server, once for the client with
--arg -addr --arg <server_ip:port>.
"""

import argparse
import base64
import os
import sys
import time

import requests
import urllib3

# Suppress insecure request warnings for development (self-signed TLS).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    parser = argparse.ArgumentParser(description="Debuglet client — submit a debuglet and stream its output")
    parser.add_argument("--dispatcher", default="localhost:9000",
                        help="Dispatcher HTTP host:port (default: localhost:9000)")
    parser.add_argument("--tls", action="store_true",
                        help="Use https/TLS (default off; local dispatcher runs with disable_tls=true)")
    parser.add_argument("--base-path", default="",
                        help="Path prefix the API is mounted under (default: '' — routes are at root)")
    parser.add_argument("--wasm", required=True, help="Path to the compiled debuglet (.wasm)")
    parser.add_argument("--executor", help="Target executor ID (defaults to the first available)")
    parser.add_argument("--arg", action="append", default=[],
                        help="Argument passed through to the debuglet as WASI argv (repeatable). "
                             "E.g. --arg -addr --arg 127.0.0.1:5201")
    parser.add_argument("--address", action="append", default=[],
                        help="Policy address for rate-limiting/accounting (repeatable)")
    parser.add_argument("--floor-bw", type=int, default=0, help="Policy floor bandwidth (bits/s)")
    parser.add_argument("--ceil-bw", type=int, default=1_000_000_000, help="Policy ceil bandwidth (bits/s)")
    parser.add_argument("--timeout-ms", type=int, default=300_000, help="Debuglet timeout (ms)")
    parser.add_argument("--start-in", type=int, help="Start the debuglet N seconds from now (optional)")
    args = parser.parse_args()

    scheme = "https" if args.tls else "http"
    base = f"{scheme}://{args.dispatcher}{args.base_path}"
    verify = False  # development deployments may use self-signed certificates
    headers = {"Debuglet-API-Version": "1.2"}

    # 1. Fetch available executors.
    print(f"[*] Fetching executors from {base}/executors ...")
    try:
        r = requests.get(f"{base}/executors", headers=headers, verify=verify, timeout=5)
        r.raise_for_status()
        executors = r.json() or []
    except Exception as e:
        print(f"[-] Failed to fetch executors: {e}")
        sys.exit(1)

    if not executors:
        print("[-] No executors connected to the dispatcher.")
        sys.exit(1)

    executor_id = args.executor
    if not executor_id:
        executor_id = executors[0]["id"]
        print(f"[*] Picking first available executor: {executor_id}")
    elif not any(e["id"] == executor_id for e in executors):
        print(f"[-] Executor '{executor_id}' not found. Available: {[e['id'] for e in executors]}")
        sys.exit(1)

    # 2. Read and base64-encode the wasm (StdEncoding, matching APIToSpec).
    if not os.path.exists(args.wasm):
        print(f"[-] WASM file not found: {args.wasm}")
        sys.exit(1)
    with open(args.wasm, "rb") as f:
        wasm_b64 = base64.b64encode(f.read()).decode("ascii")

    # 3. Submit the debuglet. PUT /debuglet takes a JSON ARRAY of DebugletRequest.
    req = {
        "order_id": 0,
        "executor_id": executor_id,
        "wasm": wasm_b64,
        "args": args.arg,
        "policy": {
            "floor_bw": args.floor_bw,
            "ceil_bw": args.ceil_bw,
            "timeout_ms": args.timeout_ms,
            "addresses": args.address,
        },
    }
    if args.start_in is not None:
        req["start_time"] = int(time.time()) + args.start_in

    print(f"[*] Creating TEST payment intent for executor {executor_id} ...")
    try:
        r = requests.put(
            f"{base}/payment/intent",
            json={"debuglets": [req], "payment_method": "TEST", "refund_address": ""},
            headers=headers,
            verify=verify,
            timeout=15,
        )
        r.raise_for_status()
        intent = r.json()["intent"]
        submission = {
            "debuglets": [req],
            "transaction_id": intent["transaction_id"],
            "auth_key": intent["auth_key"],
        }
        print(f"[*] Submitting debuglet (args={args.arg}) ...")
        r = requests.put(
            f"{base}/debuglet", json=submission, headers=headers, verify=verify, timeout=15
        )
        r.raise_for_status()
        ids = r.json()
    except Exception as e:
        body = getattr(getattr(e, "response", None), "text", "")
        print(f"[-] Failed to submit debuglet: {e}\n[-] Response: {body}")
        sys.exit(1)

    if not ids:
        print("[-] Dispatcher returned no debuglet IDs.")
        sys.exit(1)
    debuglet_id = ids[0]
    print(f"[+] Debuglet created: {debuglet_id}")

    # 4. Poll the paginated log endpoint until the run exits.
    follow_logs(base, debuglet_id, headers, verify)


def follow_logs(base, debuglet_id, headers, verify):
    """Print new log records until the dispatcher reports RunStateExited."""
    url = f"{base}/debuglet/{debuglet_id}/logs"
    print(f"[*] Following output from {url} ...\n")
    after = 0
    try:
        while True:
            response = requests.get(
                url,
                params={"after": after, "limit": 100},
                headers=headers,
                verify=verify,
                timeout=15,
            )
            response.raise_for_status()
            page = response.json()
            for entry in page.get("logs") or []:
                output = base64.b64decode(entry["output"])
                sys.stdout.buffer.write(output)
                sys.stdout.buffer.flush()
            after = page.get("after", after)
            if page.get("state") == "RunStateExited" and not page.get("has_more"):
                if page.get("error"):
                    print(f"\n[-] {page['error']}")
                break
            if not page.get("has_more"):
                time.sleep(0.25)
    except KeyboardInterrupt:
        print("\n[*] Interrupted; stopping log polling.")
    except Exception as e:
        body = getattr(getattr(e, "response", None), "text", "")
        print(f"\n[-] Failed to follow debuglet logs: {e}\n[-] Response: {body}")
        sys.exit(1)
    print("\n[*] Run finished.")


if __name__ == "__main__":
    main()
