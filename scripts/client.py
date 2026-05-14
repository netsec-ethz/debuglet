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

import argparse
import base64
import json
import os
import sys
import requests
import websocket
import urllib3
import ssl

# Suppress insecure request warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser(description="Debuglet Client - Interact with Dispatcher API")
    parser.add_argument("--dispatcher", default="localhost:9000", help="Dispatcher HTTP address (e.g., localhost:9000)")
    parser.add_argument("--wasm", required=True, help="Path to compiled WASM code (.wasm)")
    parser.add_argument("--executor", help="Target Executor ID (picks first available if not set)")
    parser.add_argument("--addr", action="append", help="Address to pass to debuglet (can be specified multiple times)")
    args = parser.parse_args()

    # Use HTTPS as dispatcher starts with StartTLS
    dispatcher_url = f"https://{args.dispatcher}"
    
    # 1. Fetch available executors
    print(f"[*] Fetching executors from {dispatcher_url}/executors...")
    try:
        r = requests.get(f"{dispatcher_url}/executors", verify=False, timeout=5)
        r.raise_for_status()
        executors = r.json()
    except Exception as e:
        print(f"[-] Failed to fetch executors: {e}")
        sys.exit(1)

    if not executors:
        print("[-] No executors connected to dispatcher.")
        sys.exit(1)

    # Resolve Executor ID
    executor_id = args.executor
    if not executor_id:
        # Sort by capacity or just pick first
        executor_id = executors[0]["id"]
        print(f"[*] Picking first available executor: {executor_id}")
    else:
        # Validate existence
        if not any(e["id"] == executor_id for e in executors):
            print(f"[-] Executor '{executor_id}' not found in dispatcher list.")
            print(f"[*] Available: {[e['id'] for e in executors]}")
            sys.exit(1)

    # 2. Read and encode WASM file
    print(f"[*] Reading WASM file: {args.wasm}")
    if not os.path.exists(args.wasm):
        print(f"[-] File not found: {args.wasm}")
        sys.exit(1)
        
    try:
        with open(args.wasm, "rb") as f:
            wasm_bytes = f.read()
            wasm_b64 = base64.b64encode(wasm_bytes).decode("utf-8")
    except Exception as e:
        print(f"[-] Failed to read/encode WASM: {e}")
        sys.exit(1)

    # 3. Submit measurement request
    print(f"[*] Submitting measurement to executor {executor_id}...")
    payload = {
        "debuglets": [
            {
                "executor_id": executor_id,
                "code": wasm_b64,
                "addresses": args.addr or [],
                "policy": {
                    "floor_bw": 0,
                    "ceil_bw": 1000000000, # 1Gbps default
                    "timeout_ms": 300000,   # 5m default
                    "destinations": []
                }
            }
        ]
    }
    
    try:
        r = requests.post(f"{dispatcher_url}/measurements", json=payload, verify=False, timeout=10)
        r.raise_for_status()
        measurement_id = r.json()
        print(f"[+] Measurement created successfully. ID: {measurement_id}")
    except Exception as e:
        print(f"[-] Failed to create measurement: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"[-] Response: {e.response.text}")
        sys.exit(1)

    # 4. Connect to WebSocket for streaming logs and triggering start
    ws_url = f"wss://{args.dispatcher}/measurements/{measurement_id}/start"
    print(f"[*] Connecting to measurement stream: {ws_url}")

    def on_message(ws, message):
        try:
            ev = json.loads(message)
            event_type = ev.get("event")
            
            if event_type == "ready":
                print(f"[*] Executor {ev.get('executor_id')} is READY (Session: {ev.get('session_id')[:8]})")
                print(f"[*] SCION Address: {ev.get('scion_addr')}")
                print("[*] Sending 'start' command...")
                ws.send("start")
                
            elif event_type == "stdout":
                # Stream stdout directly
                print(ev.get("stdout"), end="", flush=True)
                
            elif event_type == "error":
                print(f"\n[-] Dispatcher error: {ev.get('message')}")
                
            else:
                # Other events (e.g. key disclosure info if implemented in JSON)
                pass
                
        except json.JSONDecodeError:
            # Fallback for non-JSON messages
            if message.startswith("error:"):
                print(f"\n[-] {message}")
            else:
                print(f"\n[*] Message: {message}")

    def on_error(ws, error):
        print(f"[-] WebSocket Error: {error}")

    def on_close(ws, close_status_code, close_msg):
        print(f"\n[*] Connection closed ({close_status_code}): {close_msg or 'Normal closure'}")

    def on_open(ws):
        print("[+] WebSocket connected. Waiting for executor setup...")

    # Configure WebSocket to skip TLS verification
    ws = websocket.WebSocketApp(
        ws_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )

    try:
        ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Closing...")
        ws.close()

if __name__ == "__main__":
    main()
