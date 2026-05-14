#!/usr/bin/env python3
import requests
import argparse
import sys
import json
import urllib3
import ssl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser(description="Verify a pcap file using the debuglet dispatcher API")
    parser.add_argument("--server", default="https://localhost:9000", help="Dispatcher API server address")
    parser.add_argument("--pcap", required=True, help="Path to the pcap file to verify")
    parser.add_argument("--measurement", required=True, help="Measurement ID to verify against")
    
    args = parser.parse_args()

    url = f"{args.server.rstrip('/')}/verify"
    
    try:
        with open(args.pcap, "rb") as f:
            files = {"pcap": (args.pcap, f, "application/vnd.tcpdump.pcap")}
            data = {"measurement_id": args.measurement}
            
            print(f"Uploading {args.pcap} to {url} for measurement {args.measurement}...")
            response = requests.post(url, files=files, data=data, verify=False)
            
        if response.status_code != 200:
            print(f"Error: Server returned status code {response.status_code}")
            print(response.text)
            sys.exit(1)
            
        results = response.json()
        
        valid_count = sum(1 for r in results if r.get("valid"))
        total_count = len(results)
        
        print(f"\nVerification Results: {valid_count}/{total_count} packets valid")
        print("-" * 80)
        print(f"{'Timestamp':<30} | {'Source IP':<15} | {'Dest IP':<15} | {'Tag':<6} | {'Valid'}")
        print("-" * 80)
        
        for r in results:
            tag_hex = f"0x{r['tag']:04x}"
            valid_str = "YES" if r["valid"] else f"NO ({r.get('error', 'unknown error')})"
            print(f"{r['timestamp']:<30} | {r['source_ip']:<15} | {r['dest_ip']:<15} | {tag_hex:<6} | {valid_str}")
            
    except FileNotFoundError:
        print(f"Error: File not found: {args.pcap}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to dispatcher at {args.server}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
