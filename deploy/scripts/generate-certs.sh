#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich

# Generate TLS certificates for deployment.
#
# Creates a shared CA, a dispatcher server cert, and per-executor client certs.
# All certs are placed in deploy/certs/ (gitignored — keep ca.key secure).
#
# Usage:
#   ./deploy/scripts/generate-certs.sh <executor-id> [executor-id ...]
#
# The executor-id must match the executor_id field in your Ansible inventory
# (used as the TLS CN, which the dispatcher extracts to identify executors).
#
# To auto-generate IDs from the Ansible inventory:
#   cd deploy/ansible
#   IDS=$(ansible-inventory -i inventory/hosts.yml --list \
#       | python3 -c "
#   import sys, json
#   inv = json.load(sys.stdin)
#   meta = inv.get('_meta', {}).get('hostvars', {})
#   executors = inv.get('executors', {}).get('hosts', [])
#   print(' '.join(meta.get(h, {}).get('executor_id', h) for h in executors))
#   ")
#   ../../scripts/generate-certs.sh $IDS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"
DAYS=730  # 2-year validity

mkdir -p "${CERTS_DIR}/dispatcher"

# ---- CA ----------------------------------------------------------------------
if [ ! -f "${CERTS_DIR}/ca.key" ]; then
    echo "==> Generating CA..."
    openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes \
        -key "${CERTS_DIR}/ca.key" \
        -sha256 -days ${DAYS} \
        -subj "/CN=Debuglet-CA/O=Debuglet" \
        -out "${CERTS_DIR}/ca.crt"
    echo "    CA certificate: ${CERTS_DIR}/ca.crt"
    echo "    CA private key: ${CERTS_DIR}/ca.key  [keep secret]"
else
    echo "==> CA already exists, reusing."
fi

# ---- Dispatcher server cert --------------------------------------------------
if [ ! -f "${CERTS_DIR}/dispatcher/server.crt" ]; then
    echo "==> Generating dispatcher server certificate..."
    openssl genrsa -out "${CERTS_DIR}/dispatcher/server.key" 2048 2>/dev/null
    openssl req -new \
        -key "${CERTS_DIR}/dispatcher/server.key" \
        -subj "/CN=dispatcher/O=Debuglet" \
        -out "${CERTS_DIR}/dispatcher/server.csr"
    openssl x509 -req \
        -in "${CERTS_DIR}/dispatcher/server.csr" \
        -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out "${CERTS_DIR}/dispatcher/server.crt" \
        -days ${DAYS} -sha256 2>/dev/null
    rm -f "${CERTS_DIR}/dispatcher/server.csr"
    echo "    -> ${CERTS_DIR}/dispatcher/"
else
    echo "==> Dispatcher cert already exists, skipping."
fi

# ---- Per-executor client certs -----------------------------------------------
if [ $# -eq 0 ]; then
    echo ""
    echo "No executor IDs provided — only CA and dispatcher cert generated."
    echo "Run with executor IDs to generate executor client certs:"
    echo "  $0 executor-node1 executor-node2 ..."
    exit 0
fi

mkdir -p "${CERTS_DIR}/executors"

for EXECUTOR_ID in "$@"; do
    EXEC_DIR="${CERTS_DIR}/executors/${EXECUTOR_ID}"
    if [ -d "${EXEC_DIR}" ]; then
        echo "==> Cert for '${EXECUTOR_ID}' already exists, skipping."
        continue
    fi
    mkdir -p "${EXEC_DIR}"
    echo "==> Generating client cert for executor: ${EXECUTOR_ID}"
    openssl genrsa -out "${EXEC_DIR}/client.key" 2048 2>/dev/null
    openssl req -new \
        -key "${EXEC_DIR}/client.key" \
        -subj "/CN=${EXECUTOR_ID}/O=Debuglet" \
        -out "${EXEC_DIR}/client.csr"
    openssl x509 -req \
        -in "${EXEC_DIR}/client.csr" \
        -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out "${EXEC_DIR}/client.crt" \
        -days ${DAYS} -sha256 2>/dev/null
    rm -f "${EXEC_DIR}/client.csr"
    echo "    -> ${EXEC_DIR}/"
done

echo ""
echo "Certificate tree:"
find "${CERTS_DIR}" -name "*.crt" | sort | sed 's|^|  |'
