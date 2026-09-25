#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich

# Generate the TLS material a deployment installs.
#
# Creates a shared CA, one dispatcher server certificate and one client
# certificate per executor. Everything is written to deploy/certs/, which is
# gitignored; keep ca.key secret.
#
# Usage:
#   DISPATCHER_SANS="DNS:dispatcher.example.com,IP:203.0.113.10" \
#       ./deploy/scripts/generate-certs.sh <executor-id> [executor-id ...]
#
# DISPATCHER_SANS is required and has no default. An executor verifies the
# certificate the dispatcher presents against the name it dialled, and a
# certificate is identified by its subjectAltName only — a common name alone
# is not accepted by the client, so a certificate without the right entries
# here cannot be connected to. List every name and address an executor may
# dial, as OpenSSL entries separated by commas:
#
#   DNS:dispatcher.example.com   the dispatcher_addr executors are given
#   IP:203.0.113.10              the same host by address
#   DNS:debuglet.example.com     any other name a client uses for the API
#
# If a proxy fronts the API, the name clients use for the proxy belongs here
# too, on the certificate the proxy serves.
#
# The executor-id must match the executor_id in the inventory: a UUID, which
# becomes the certificate's common name and is how the dispatcher identifies
# the executor. Client certificates carry no subjectAltName; they are
# identified by that name, and they carry the client-authentication extended
# key usage, without which an executor's certificate is refused.
#
# Every leaf here is issued directly by the CA this script creates, so a leaf
# file is already a complete chain to the configured root. Material from
# another authority is not: a leaf file must then hold the leaf followed by
# every intermediate up to the root in ca.crt, or the other side cannot build
# the chain. An authority whose root certificate has expired is refused
# outright, so reissue the CA before it runs out rather than after.
#
# Environment:
#   DISPATCHER_SANS  required, as above
#   CERTS_DIR        output directory (default deploy/certs)
#   DAYS             validity in days (default 730)
#
# `make deploy-certs DISPATCHER_SANS=...` reads executor IDs from the
# inventory (including child groups), generates certificates and installs them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CERTS_DIR:-${SCRIPT_DIR}/../certs}"
DAYS="${DAYS:-730}"
SANS="${DISPATCHER_SANS:-}"

if [ -z "${SANS}" ]; then
	cat >&2 <<'USAGE'
generate-certs: DISPATCHER_SANS is required and has no default.

An executor verifies the dispatcher's certificate against the name it dialled,
so the certificate has to carry that name. Name every address an executor or a
client may use:

  DISPATCHER_SANS="DNS:dispatcher.example.com,IP:203.0.113.10" \
      ./deploy/scripts/generate-certs.sh <executor-id> ...
USAGE
	exit 2
fi

# Reject anything that is not a plain DNS or IP entry rather than passing it
# into an extension file.
IFS=',' read -r -a san_entries <<<"${SANS}"
for entry in "${san_entries[@]}"; do
	case "${entry}" in
		DNS:*|IP:*) ;;
		*) echo "generate-certs: unsupported subjectAltName entry '${entry}'; use DNS:name or IP:address" >&2; exit 2 ;;
	esac
	value=${entry#*:}
	case "${value}" in
		''|*[!A-Za-z0-9.:_-]*) echo "generate-certs: invalid subjectAltName value in '${entry}'" >&2; exit 2 ;;
	esac
done

mkdir -p "${CERTS_DIR}/dispatcher"
chmod 700 "${CERTS_DIR}"
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-certs.XXXXXXXX")"
trap 'rm -rf -- "${work}"' EXIT INT TERM

# A leaf certificate is usable only with these extensions: a client checks
# basic constraints and key usage, matches the name against subjectAltName,
# and refuses a certificate whose extended key usage does not cover the role
# it is being used for.
cat >"${work}/server.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = ${SANS}
EXT
cat >"${work}/client.ext" <<'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXT

sign() {
	local name=$1 key=$2 crt=$3 ext=$4
	openssl req -new -key "${key}" -subj "/CN=${name}/O=Debuglet" -out "${work}/csr"
	openssl x509 -req -in "${work}/csr" \
		-CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial \
		-extfile "${ext}" -out "${crt}" -days "${DAYS}" -sha256 2>/dev/null
	rm -f "${work}/csr"
}

# ---- CA ----------------------------------------------------------------------
if [ ! -f "${CERTS_DIR}/ca.key" ]; then
	echo "==> Generating CA..."
	openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
	chmod 600 "${CERTS_DIR}/ca.key"
	openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key" -sha256 -days "${DAYS}" \
		-subj "/CN=Debuglet-CA/O=Debuglet" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-out "${CERTS_DIR}/ca.crt"
	echo "    CA certificate: ${CERTS_DIR}/ca.crt"
	echo "    CA private key: ${CERTS_DIR}/ca.key  [keep secret]"
else
	echo "==> CA already exists, reusing."
fi

# ---- Dispatcher server certificate -------------------------------------------
# The names are an input, so an existing certificate is reissued when they
# change: keeping one that does not carry the current dispatcher address would
# leave every executor unable to connect.
server_crt="${CERTS_DIR}/dispatcher/server.crt"
current_sans=""
if [ -f "${server_crt}" ]; then
	current_sans="$(openssl x509 -in "${server_crt}" -noout -ext subjectAltName 2>/dev/null |
		tail -n +2 | tr -d ' ' | sed 's/IPAddress:/IP:/g')"
fi
wanted_sans="$(printf '%s' "${SANS}" | tr -d ' ')"
if [ ! -f "${server_crt}" ]; then
	echo "==> Generating dispatcher server certificate for ${SANS}..."
elif [ "${current_sans}" != "${wanted_sans}" ]; then
	echo "==> Reissuing dispatcher server certificate: names changed"
	echo "    from ${current_sans:-none}"
	echo "    to   ${wanted_sans}"
else
	echo "==> Dispatcher certificate already covers ${SANS}, keeping it."
fi
if [ ! -f "${server_crt}" ] || [ "${current_sans}" != "${wanted_sans}" ]; then
	openssl genrsa -out "${CERTS_DIR}/dispatcher/server.key" 2048 2>/dev/null
	chmod 600 "${CERTS_DIR}/dispatcher/server.key"
	sign dispatcher "${CERTS_DIR}/dispatcher/server.key" "${server_crt}" "${work}/server.ext"
	echo "    -> ${CERTS_DIR}/dispatcher/"
fi

# ---- Per-executor client certificates ----------------------------------------
if [ $# -eq 0 ]; then
	echo ""
	echo "No executor IDs given — only the CA and the dispatcher certificate exist."
	echo "Run with the executor IDs from the inventory to add client certificates:"
	echo "  DISPATCHER_SANS='${SANS}' $0 <executor-uuid> ..."
	exit 0
fi

mkdir -p "${CERTS_DIR}/executors"
for EXECUTOR_ID in "$@"; do
	EXEC_DIR="${CERTS_DIR}/executors/${EXECUTOR_ID}"
	if [ -f "${EXEC_DIR}/client.crt" ]; then
		echo "==> Certificate for '${EXECUTOR_ID}' already exists, keeping it."
		continue
	fi
	mkdir -p "${EXEC_DIR}"
	echo "==> Generating client certificate for executor: ${EXECUTOR_ID}"
	openssl genrsa -out "${EXEC_DIR}/client.key" 2048 2>/dev/null
	chmod 600 "${EXEC_DIR}/client.key"
	sign "${EXECUTOR_ID}" "${EXEC_DIR}/client.key" "${EXEC_DIR}/client.crt" "${work}/client.ext"
	echo "    -> ${EXEC_DIR}/"
done

echo ""
echo "Certificate tree:"
find "${CERTS_DIR}" -name "*.crt" | sort | sed 's|^|  |'
