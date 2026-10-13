#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Install the verified delivery demo on an existing, guarded six-pod inventory.

Usage: bootstrap.py --state /absolute/private/directory
The launcher supplies inventory.json, ssh_key and known_hosts. This program makes
no cloud API calls. --remote operations run this same file on the selected pods.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

BASE = Path("/workspace/debuglet-demo")
ROLES = ["dispatcher"] + [f"executor-{i}" for i in range(1, 6)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        stream.write(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(path):
    with Path(path).open("rb") as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
        return result.hexdigest()


def utc(value):
    require(type(value) in (int, float) and math.isfinite(value) and value > 0,
            "expiry must be a finite Unix timestamp")
    return value


def public_ipv4(value):
    address = ipaddress.ip_address(value)
    require(address.version == 4 and address.is_global, "peer must have a global IPv4 address")
    return str(address)


def port(value):
    require(type(value) is int and 1 <= value <= 65535, "actual mapped port is invalid")
    return value


def validate_inventory(value):
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value["run_id"]), "invalid run ID")
    utc(value["expires_at"])
    pods = value["pods"]
    require(len(pods) == 6 and {p["role"] for p in pods} == set(ROLES),
            "expected one dispatcher and five executors")
    require(len({p["id"] for p in pods}) == 6, "duplicate pod ID")
    for pod in pods:
        require(re.fullmatch(r"[A-Za-z0-9_-]{6,64}", pod["id"]), "invalid pod ID")
        public_ipv4(pod["public_ip"])
        port(pod["ssh_port"])
        if pod["role"] == "dispatcher":
            port(pod["api_port"])
            port(pod["control_port"])
            require(pod["console_url"].rstrip("/") ==
                    f'https://{pod["id"]}-8080.proxy.runpod.net', "unexpected console origin")
        else:
            port(pod["peer_port"])
    peers = [(p["public_ip"], p["peer_port"]) for p in pods if p["role"] != "dispatcher"]
    require(len(set(peers)) == 5, "duplicate peer endpoint")
    package = value["package"]
    require(re.fullmatch(r"v[0-9A-Za-z.+-]+", package["version"]),
            "invalid package version")
    for key in ("sha256", "console_sha256", "installer_sha256", "checksums_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", package[key]), "missing package digest")
    return value


def package_files(package):
    directory = Path(package["directory"])
    require(directory.is_absolute(), "package directory must be absolute")
    archive, console = Path(package["archive"]), Path(package["console_archive"])
    if not archive.is_absolute():
        require(archive.name == str(archive), "archive must be a filename or absolute path")
        archive = directory / archive
    if not console.is_absolute():
        require(console.name == str(console), "console must be a filename or absolute path")
        console = directory / console
    require(archive.name == f'debuglet-{package["version"]}-linux-amd64.tar.gz',
            "archive name differs from version")
    files = {archive.name: (archive, package["sha256"]),
             "install.sh": (directory / "install.sh", package["installer_sha256"]),
             "SHA256SUMS": (directory / "SHA256SUMS", package["checksums_sha256"]),
             "console.tar.gz": (console, package["console_sha256"])}
    for path, expected in files.values():
        require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                "selected package file does not match its digest")
    return files


def run(arguments, *, data=None, timeout=120):
    result = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed (exit {result.returncode}); inspect private host logs")
    return result.stdout


class Host:
    def __init__(self, state, pod):
        self.pod = pod
        self.options = ["ssh", "-F", "/dev/null", "-i", str(state / "ssh_key"),
                        "-p", str(pod["ssh_port"]), "-o", "BatchMode=yes",
                        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                        "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=15",
                        "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=15",
                        "-o", "ServerAliveCountMax=2", "-o", "HostKeyAlias=" + pod["id"],
                        "-o", "UserKnownHostsFile=" + str(state / "known_hosts"),
                        "root@" + pod["public_ip"]]

    def command(self, command, *, data=None, timeout=120):
        return run(self.options + [command], data=data, timeout=timeout)

    def copy(self, source, destination):
        with Path(source).open("rb") as stream:
            result = subprocess.run(self.options + ["umask 077; cat > " + shlex.quote(str(destination))],
                                    stdin=stream, capture_output=True, timeout=300)
        require(result.returncode == 0, "package transfer failed")

    def remote(self, action, value, timeout=120):
        output = self.command(shlex.join(["python3", str(BASE / "bootstrap.py"), "--remote", action]),
                              data=json.dumps(value).encode(), timeout=timeout)
        return json.loads(output)


def denied_networks(addresses):
    networks = [ipaddress.ip_network("0.0.0.0/0")]
    for value in sorted(set(addresses)):
        allowed = ipaddress.ip_network(public_ipv4(value) + "/32")
        networks = [part for network in networks for part in
                    (list(network.address_exclude(allowed)) if allowed.subnet_of(network) else [network])]
    return ",".join(map(str, networks)) + ",::/0"


def executor_config(text, pod, peers):
    require(text.count("[network]\n") == 1, "join configuration has no unique network section")
    text = text.replace("[network]\n", "[network]\npublic_host = " + json.dumps(pod["public_ip"]) +
                        "\npublic_ports = " + json.dumps(str(pod["peer_port"])) + "\n")
    policy = ('[network.policy]\nlocal_targets = false\ntcp = true\ntls = false\n'
              'udp = false\nicmp = false\nscion = false\ninbound = true\npermitted_ports = ' +
              json.dumps(",".join(map(str, sorted({p["peer_port"] for p in peers})))) +
              '\ndenied_destinations = ' + json.dumps(denied_networks(p["public_ip"] for p in peers)) + '\n')
    text, count = re.subn(r"(?ms)^\[network\.policy\]\n.*?(?=^\[|\Z)", lambda _: policy, text)
    require(count == 1, "join configuration has no unique policy")
    require("[connectivity]" not in text, "unexpected existing connectivity section")
    return text + "\n[connectivity]\nlisteners = true\n"


def dispatcher_config(pod):
    origin = pod["console_url"].rstrip("/")
    return f'''[server]
bind_host = "0.0.0.0"
http_port = 9000
grpc_port = 9001
local_development = false
[tls]
disable = false
cert_file = "{BASE}/config/server.crt"
key_file = "{BASE}/config/server.key"
ca_file = "{BASE}/config/ca.crt"
require_client_cert = true
[database]
path = "{BASE}/state/dispatcher.sqlite"
[scheduler]
executor_timeout = 30
scheduler_granularity_ms = 100
[sui]
disabled = true
[executor_onboarding]
enabled = true
ca_cert = "{BASE}/config/issuer.crt"
ca_key = "{BASE}/config/issuer.key"
dispatcher_url = "{origin}/api"
grpc_address = "{pod['public_ip']}:{pod['control_port']}"
yamux_address = "{pod['public_ip']}:{pod['api_port']}"
[cors]
allowed_origins = ["{origin}"]
[github_oauth]
enabled = false
'''


def listener_config(pod, peers, executors):
    require(len(peers) == len(executors) == 5 and
            {p["role"] for p in peers} == {e["role"] for e in executors} == set(ROLES[1:]),
            "listener configuration requires exactly five known executor roles")
    by_role = {item["role"]: item for item in executors}
    require(len({item["executor_id"] for item in executors}) == 5, "duplicate enrolled executor ID")
    contents = dispatcher_config(pod)
    for peer in sorted(peers, key=lambda item: item["role"]):
        enrolled = by_role[peer["role"]]
        node = enrolled["executor_id"]
        require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", node),
                "invalid enrolled executor ID")
        address, number = public_ipv4(peer["public_ip"]), port(peer["peer_port"])
        require((enrolled["peer_ip"], enrolled["peer_port"]) == (address, number),
                "enrolled endpoint differs from the selected inventory")
        region = peer["region"]
        label = f'{peer["role"]} ({region} provider region)'
        require(re.fullmatch(r"[A-Z0-9-]+", region) and len(label) <= 64, "invalid provider region label")
        contents += (f'\n[executors."{node}"]\nconnectivity_host = {json.dumps(address)}\n'
                     f'connectivity_ports = "{number}"\ndisplay_name = {json.dumps(label)}\n')
        country = "NL" if region.startswith("EU-NL") else "US" if region.startswith("US-") else None
        if country:
            contents += f'country = "{country}"\n'
    return contents


def remote_configure_listeners(value):
    pod, package = value["pod"], value["package"]
    require(pod["role"] == "dispatcher", "listener configuration belongs on the dispatcher")
    identity = {"run_id": value["run_id"], "sha256": package["sha256"], "pod_id": pod["id"],
                "console_sha256": package["console_sha256"]}
    for name in ("setup.json", "installed.json"):
        require(json.loads((BASE / name).read_text()) == identity, "dispatcher setup ownership differs")
    contents = listener_config(pod, value["peers"], value["executors"])
    expected = hashlib.sha256(contents.encode()).hexdigest()
    config, candidate = BASE / "config/dispatcher.toml", BASE / "config/dispatcher.candidate.toml"
    marker = BASE / "listeners-applied.json"
    require(config.is_file() and not config.is_symlink() and
            config.read_text() in (dispatcher_config(pod), contents),
            "dispatcher configuration differs; preserve it and inspect before recovery")
    if config.read_text() != contents or not marker.exists() or json.loads(marker.read_text()) != {"sha256": expected}:
        save(candidate, contents)
        try:
            run(["chown", "debuglet:debuglet", str(candidate)])
            binary = f'/usr/local/lib/debuglet/{package["version"]}/bin/debuglet-dispatcher'
            run(["runuser", "-u", "debuglet", "--", binary, "-config", str(candidate), "-check-database"])
            candidate.replace(config)
            supervisor("restart", "dispatcher")
            wait_program("dispatcher")
            save(marker, {"sha256": expected})
        finally:
            candidate.unlink(missing_ok=True)
    else:
        wait_program("dispatcher")
    return {"sha256": expected}


def fresh_listener_checks(listing, expected, now):
    if not isinstance(listing, list):
        return None
    selected = [item for item in listing if item.get("id") in expected]
    if len(selected) != 5 or {item["id"] for item in selected} != expected:
        return None
    checks = []
    for item in selected:
        connectivity = item.get("connectivity") or {}
        listener = connectivity.get("tcp_listener") or {}
        observed, expires = listener.get("observed_at"), listener.get("expires_at")
        if not (item.get("ready") is True and connectivity.get("schema_version") == 1 and
                listener.get("state") == "reachable" and listener.get("source") == "dispatcher-observed" and
                listener.get("stale") is False and type(observed) is int and type(expires) is int and
                observed <= int(now) < expires):
            return None
        checks.append({"executor_id": item["id"], **listener})
    return checks


LOGIN_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to the delivery demo</title>
<style>body{font:18px system-ui;max-width:38rem;margin:12vh auto;padding:1.5rem}
label,input,button{display:block;margin:1rem 0}input{width:95%;padding:.7rem}
button{padding:.7rem 1.2rem}#message{color:#a22}</style>
<h1>Delivery demo sign-in</h1>
<p>Paste the account key from the launcher's private <code>account-key</code> file.
This signs in to your ordinary Debuglet account for this temporary demo.</p>
<form id="login"><label for="key">Account key</label>
<input id="key" type="password" autocomplete="off" required>
<button>Sign in</button></form><p id="message" role="status"></p>
<script>
document.querySelector('#login').addEventListener('submit', async (event) => {
 event.preventDefault();
 const key = document.querySelector('#key');
 const message = document.querySelector('#message');
 message.textContent = '';
 try {
  const response = await fetch('/api/auth/login', {
   method: 'POST', credentials: 'same-origin',
   headers: {'Content-Type': 'application/json', 'Debuglet-API-Version': '1.22'},
   body: JSON.stringify({account_key: key.value.trim()})
  });
  key.value = '';
  if (!response.ok) throw new Error('Sign-in failed. Check the account key.');
  window.location.assign('/console/');
 } catch (error) {
  key.value = '';
  message.textContent = 'Sign-in failed. Check the account key and try again.';
 }
});
</script></html>
"""


def nginx_config():
    return f'''pid {BASE}/nginx-tmp/nginx.pid;
error_log {BASE}/logs/nginx-error.log warn;
events {{ worker_connections 128; }}
http {{
 include /etc/nginx/mime.types;
 default_type application/octet-stream;
 client_body_temp_path {BASE}/nginx-tmp/client;
 proxy_temp_path {BASE}/nginx-tmp/proxy;
 fastcgi_temp_path {BASE}/nginx-tmp/fastcgi;
 uwsgi_temp_path {BASE}/nginx-tmp/uwsgi;
 scgi_temp_path {BASE}/nginx-tmp/scgi;
 access_log off;
 client_max_body_size 32m;
 server {{
  listen 8080;
  server_name _;
  root {BASE}/www;
  location = / {{ return 302 /demo-login; }}
  location = /demo-login {{ default_type text/html; try_files /demo-login.html =404; }}
  location = /console {{ return 302 /console/; }}
  location /console/ {{ try_files $uri $uri/ /console/index.html; }}
  location /api/ {{
   proxy_pass https://127.0.0.1:9000/;
   proxy_ssl_verify on;
   proxy_ssl_trusted_certificate {BASE}/config/ca.crt;
   proxy_ssl_server_name on;
   proxy_ssl_name localhost;
   proxy_set_header Host localhost;
   proxy_set_header X-Forwarded-Proto https;
   proxy_read_timeout 90s;
  }}
  location /ws-api/ {{
   proxy_pass https://127.0.0.1:9000/;
   proxy_ssl_verify on;
   proxy_ssl_trusted_certificate {BASE}/config/ca.crt;
   proxy_ssl_server_name on;
   proxy_ssl_name localhost;
   proxy_http_version 1.1;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection upgrade;
   proxy_read_timeout 90s;
  }}
 }}
}}
'''


def supervisor_config():
    return f'''[unix_http_server]
file={BASE}/supervisor.sock
chmod=0700
[supervisord]
logfile={BASE}/supervisord.log
logfile_maxbytes=2MB
logfile_backups=1
pidfile={BASE}/supervisord.pid
childlogdir={BASE}/logs
[rpcinterface:supervisor]
supervisor.rpcinterface_factory=supervisor.rpcinterface:make_main_rpcinterface
[supervisorctl]
serverurl=unix://{BASE}/supervisor.sock
[include]
files={BASE}/programs/*.conf
'''


def program(name, command):
    require("%" not in command and "\n" not in command, "invalid supervisor command")
    save(BASE / "programs" / (name + ".conf"), f'''[program:{name}]
command=/usr/bin/setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all {command}
user=debuglet
autostart=true
autorestart=true
startsecs=1
stopwaitsecs=10
stopasgroup=true
killasgroup=true
stdout_logfile={BASE}/logs/{name}.log
stdout_logfile_maxbytes=2MB
stdout_logfile_backups=1
redirect_stderr=true
''')


def supervisor(*arguments):
    return run(["supervisorctl", "-c", str(BASE / "supervisord.conf"), *arguments])


def reload_programs():
    supervisor("reread")
    supervisor("update")


def verify_pki(address):
    directory = BASE / "config"
    run(["openssl", "verify", "-CAfile", str(directory / "ca.crt"), "-purpose", "sslserver",
         "-verify_ip", address, str(directory / "server.crt")])
    run(["openssl", "verify", "-CAfile", str(directory / "ca.crt"), "-purpose", "sslserver",
         "-verify_hostname", "localhost", str(directory / "server.crt")])
    run(["openssl", "verify", "-CAfile", str(directory / "ca.crt"), str(directory / "issuer.crt")])
    for name in ("server", "issuer"):
        certificate_key = run(["openssl", "x509", "-in", str(directory / (name + ".crt")), "-pubkey", "-noout"])
        private_key = run(["openssl", "pkey", "-in", str(directory / (name + ".key")), "-pubout"])
        require(certificate_key == private_key, "TLS certificate/key mismatch; preserve files and inspect")


def prepare_pki(address):
    directory = BASE / "config"
    identity = ("ca.crt", "server.key", "server.crt", "issuer.key", "issuer.crt")
    temporary = ("root.key", "ca.srl", "server.csr", "server.ext", "issuer.csr", "issuer.ext")
    if any((directory / name).exists() for name in identity + temporary):
        require(all((directory / name).is_file() and not (directory / name).is_symlink() for name in identity),
                "Incomplete TLS identity; preserve config and inspect before recovery. Keys will not be replaced.")
        verify_pki(address)
        for name in temporary:
            (directory / name).unlink(missing_ok=True)
        return

    def openssl(*arguments):
        run(["openssl", *arguments])

    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(directory / "root.key"), "-out", str(directory / "ca.crt"), "-days", "2",
            "-subj", "/CN=Debuglet demo root", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, extensions in (
        ("server", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
         "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:" + address + "\n"),
        ("issuer", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
         "extendedKeyUsage=clientAuth\n"),
    ):
        save(directory / (name + ".ext"), extensions)
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", str(directory / (name + ".key")), "-out", str(directory / (name + ".csr")),
                "-subj", "/CN=" + ("localhost" if name == "server" else "Debuglet demo executor issuer"))
        openssl("x509", "-req", "-in", str(directory / (name + ".csr")), "-CA", str(directory / "ca.crt"),
                "-CAkey", str(directory / "root.key"), "-CAcreateserial", "-out", str(directory / (name + ".crt")),
                "-days", "1", "-sha256", "-extfile", str(directory / (name + ".ext")))
    verify_pki(address)
    for name in temporary:
        (directory / name).unlink(missing_ok=True)


def extract_console(archive):
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unsafe console archive member")
        names = {str(PurePosixPath(member.name)) for member in members}
        require("console/index.html" in names or "index.html" in names, "console archive has no index")
        destination = BASE / "www" if "console/index.html" in names else BASE / "www/console"
        destination.mkdir(parents=True, exist_ok=True)
        # Validate and extract regular files ourselves, without following links.
        for member in members:
            path = destination / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, path.open("wb") as target:
                    while block := source.read(1024 * 1024):
                        target.write(block)
    save(BASE / "www/demo-login.html", LOGIN_PAGE)
    for path in (BASE / "www").rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (BASE / "www").chmod(0o755)


def preserve_config(path, contents):
    if path.exists():
        require(path.is_file() and not path.is_symlink() and path.read_text() == contents,
                "Existing configuration differs; preserve it and inspect before recovery")
    else:
        save(path, contents)


def remote_setup(value):
    pod, package = value["pod"], value["package"]
    marker = BASE / "installed.json"
    identity = {"run_id": value["run_id"], "sha256": package["sha256"], "pod_id": pod["id"],
                "console_sha256": package["console_sha256"]}
    ownership = BASE / "setup.json"
    if ownership.exists():
        require(json.loads(ownership.read_text()) == identity, "existing setup belongs to another run/package/pod")
    else:
        require(not any((BASE / name).exists() for name in ("config", "state", "supervisord.conf", "installed.json")),
                "Existing runtime has no setup ownership record; preserve it and inspect before recovery")
        save(ownership, identity)
    # The SSH upload creates /workspace under umask 077 on some pod images.
    # Add traversal only to that controlled parent; do not change / or state.
    require(BASE.parent.name == "workspace" and BASE.parent.is_dir() and not BASE.parent.is_symlink(),
            "runtime parent must be the real workspace directory")
    BASE.parent.chmod((BASE.parent.stat().st_mode & 0o7777) | 0o011)
    if marker.exists():
        require(json.loads(marker.read_text()) == identity, "existing installation belongs to another run/package")
        return {"installed": True}
    archive = BASE / "package" / Path(package["archive"]).name
    for path, key in ((archive, "sha256"), (BASE / "package/install.sh", "installer_sha256"),
                      (BASE / "package/SHA256SUMS", "checksums_sha256")):
        require(digest(path) == package[key], "remote package digest mismatch")
    packages = ["openssl", "supervisor", "util-linux"]
    if pod["role"] == "dispatcher":
        packages.append("nginx")
    run(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"], timeout=300)
    run(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
         "--no-install-recommends", *packages], timeout=300)
    run(["sh", str(BASE / "package/install.sh"), "--archive", str(archive), "--checksums",
         str(BASE / "package/SHA256SUMS"), "--version", package["version"], "--prefix", "/usr/local"])
    if subprocess.run(["id", "debuglet"], capture_output=True).returncode:
        run(["useradd", "--system", "--user-group", "--create-home", "--shell", "/usr/sbin/nologin", "debuglet"])
    BASE.chmod(0o755)
    (BASE / "bootstrap.py").chmod(0o755)
    run(["install", "-d", "-m", "700", "-o", "debuglet", "-g", "debuglet",
         *[str(BASE / name) for name in ("state", "logs", "nginx-tmp", "config")]])
    (BASE / "programs").mkdir(mode=0o700, exist_ok=True)
    preserve_config(BASE / "supervisord.conf", supervisor_config())
    try:
        require(int(supervisor("pid").strip()) > 0, "invalid supervisor identity")
    except RuntimeError:
        run(["supervisord", "-c", str(BASE / "supervisord.conf")])
    if pod["role"] == "dispatcher":
        require(digest(BASE / "package/console.tar.gz") == package["console_sha256"], "console digest mismatch")
        extract_console(BASE / "package/console.tar.gz")
        prepare_pki(pod["public_ip"])
        preserve_config(BASE / "config/dispatcher.toml", dispatcher_config(pod))
        run(["chown", "-R", "debuglet:debuglet", str(BASE / "config")])
        preserve_config(BASE / "nginx.conf", nginx_config())
        (BASE / "nginx.conf").chmod(0o644)
        binary = f'/usr/local/lib/debuglet/{package["version"]}/bin/debuglet-dispatcher'
        database = BASE / "state/dispatcher.sqlite"
        if database.exists():
            run(["runuser", "-u", "debuglet", "--", binary, "-config", str(BASE / "config/dispatcher.toml"), "-check-database"])
        else:
            run(["runuser", "-u", "debuglet", "--", binary, "-init-database", str(database)])
        run(["runuser", "-u", "debuglet", "--", "nginx", "-t", "-c", str(BASE / "nginx.conf")])
        program("dispatcher", shlex.join([binary, "-config", str(BASE / "config/dispatcher.toml")]))
        program("nginx", shlex.join(["nginx", "-c", str(BASE / "nginx.conf"), "-g", "daemon off;"]))
        reload_programs()
    save(marker, identity)
    return {"installed": True}


def remote_probe_start(value):
    require(not (BASE / "join-result.json").exists(), "executor already enrolled; do not replace its listener")
    save(BASE / "config/probe.json", value)
    run(["chown", "debuglet:debuglet", str(BASE / "config/probe.json")])
    program("peer-probe", shlex.join(["python3", str(BASE / "bootstrap.py"), "--probe-server"]))
    reload_programs()
    # update starts asynchronously and startsecs requires a full second.
    wait_program("peer-probe")
    return {"listening": True}


def wait_program(name):
    for _ in range(20):
        result = subprocess.run(["supervisorctl", "-c", str(BASE / "supervisord.conf"), "status", name],
                                capture_output=True, timeout=10)
        if result.returncode == 0 and b"RUNNING" in result.stdout:
            return
        time.sleep(0.5)
    raise RuntimeError("supervised process did not become running")


def probe_server():
    value = json.loads((BASE / "config/probe.json").read_text())
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", value["pod"]["peer_port"]))
        listener.listen(16)
        listener.settimeout(1)
        while time.time() < utc(value["expires_at"]):
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                continue
            with connection:
                try:
                    connection.settimeout(3)
                    request = json.loads(connection.makefile("rb").readline(4096))
                    if request.get("token") != value["token"] or request.get("role") not in ROLES[1:]:
                        continue
                    response = {"role": value["pod"]["role"], "source_role": request["role"],
                                "source_ip": peer[0], "source_port": peer[1], "token": value["token"]}
                    connection.sendall(json.dumps(response).encode() + b"\n")
                except (OSError, ValueError):
                    continue


def remote_probe_client(value):
    observations = []
    for target in value["peers"]:
        if target["role"] == value["pod"]["role"]:
            continue
        with socket.create_connection((target["public_ip"], target["peer_port"]), timeout=10) as connection:
            connection.sendall(json.dumps({"token": value["token"], "role": value["pod"]["role"]}).encode() + b"\n")
            reply = json.loads(connection.makefile("rb").readline(4096))
        require(reply.pop("token", None) == value["token"] and reply.get("role") == target["role"] and
                reply.get("source_role") == value["pod"]["role"], "peer preflight identity mismatch")
        observations.append({**reply, "target_ip": target["public_ip"], "target_port": target["peer_port"]})
    return observations


def remote_probe_stop(_value):
    path = BASE / "programs/peer-probe.conf"
    if path.exists():
        # Removing a config through update stops its process as a group.
        path.unlink()
        reload_programs()
    (BASE / "config/probe.json").unlink(missing_ok=True)
    return {"stopped": True}


def validate_preflight(peers, observations):
    expected = {(source["role"], target["role"]) for source in peers for target in peers if source != target}
    actual = {(item["source_role"], item["role"]) for item in observations}
    require(len(observations) == 20 and actual == expected, "all 20 directed peer connections must succeed")
    by_role = {pod["role"]: pod for pod in peers}
    for item in observations:
        public_ipv4(item["source_ip"])
        require(item["source_ip"] == by_role[item["source_role"]]["public_ip"],
                "observed source differs from advertised peer IP; exact guest policy would reject it")
        target = by_role[item["role"]]
        require((item["target_ip"], item["target_port"]) == (target["public_ip"], target["peer_port"]),
                "preflight target differs from selected peer")


def remote_join(value):
    result_path = BASE / "join-result.json"
    if result_path.exists():
        result = json.loads(result_path.read_text())
        require(result["executor_id"] == value["enrollment"]["executor"]["id"], "existing executor identity differs")
        return result
    node = value["enrollment"]["executor"]["id"]
    require(re.fullmatch(r"[0-9a-f-]{36}", node), "invalid enrolled executor ID")
    state = BASE / "state" / ("executor-" + node)
    checkpoint_path = BASE / "join-checkpoint.json"
    if not checkpoint_path.exists():
        require(not state.exists(), "Executor state exists without an enrollment checkpoint. Preserve " +
                str(state) + "; inspect its service.toml and certificate before manual recovery. "
                "If recovery is impossible, stop the old executor and obtain a fresh setup token "
                "for a new state directory. This bootstrap will not reuse the old token.")
        token_file = BASE / "config/setup-token"
        save(token_file, value["enrollment"]["token"] + "\n")
        run(["chown", "debuglet:debuglet", str(token_file)])
        try:
            output = run(["runuser", "-u", "debuglet", "--", "/usr/local/bin/dbl", "--output", "json",
                          "executor", "join", "--dispatcher", value["api_url"], "--executor", node,
                          "--state-dir", str(state), "--token-file", str(token_file)], timeout=90)
        finally:
            token_file.unlink(missing_ok=True)
        config = Path(json.loads(output)["config"])
        require(config in (state / "executor.toml", state / "service.toml"), "unexpected join config path")
        # Publish before any configuration or supervisor changes. Retain the
        # original configuration so retries never duplicate edited TOML keys.
        save(checkpoint_path, {"executor_id": node, "config": str(config),
                               "original_config": config.read_text(),
                               "certificate_sha256": digest(state / "executor.crt")})
    checkpoint = json.loads(checkpoint_path.read_text())
    require(checkpoint["executor_id"] == node, "enrollment checkpoint belongs to another executor")
    config = Path(checkpoint["config"])
    require(config in (state / "executor.toml", state / "service.toml"), "unexpected join config path")
    require(digest(state / "executor.crt") == checkpoint["certificate_sha256"],
            "enrolled certificate changed; preserve state and inspect before recovery")
    save(config, executor_config(checkpoint["original_config"], value["pod"], value["peers"]))
    run(["chown", "debuglet:debuglet", str(config)])
    binary = f'/usr/local/lib/debuglet/{value["version"]}/bin/debuglet-executor'
    program("executor", shlex.join([binary, "-config", str(config)]))
    reload_programs()
    wait_program("executor")
    result = {"executor_id": node, "role": value["pod"]["role"], "peer_ip": value["pod"]["public_ip"],
              "peer_port": value["pod"]["peer_port"], "certificate_sha256": digest(state / "executor.crt")}
    save(result_path, result)
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class API:
    def __init__(self, origin):
        self.origin, self.token = origin, None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, body=None):
        headers = {"Accept": "application/json", "Debuglet-API-Version": "1.22", "User-Agent": "DebugletDemo/1.0"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.origin + path, method=method, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"dispatcher API returned HTTP {error.code}") from None
        require(len(data) <= 1024 * 1024, "oversized API response")
        return json.loads(data) if data else None


def bootstrap(state):
    require(state.is_absolute() and state.is_dir(), "--state must name an existing absolute directory")
    os.chmod(state, 0o700)
    inventory = validate_inventory(json.loads((state / "inventory.json").read_text()))
    require(time.time() < utc(inventory["expires_at"]) - 300, "too little lifetime remains for bootstrap")
    files = package_files(inventory["package"])
    hosts = {pod["role"]: Host(state, pod) for pod in inventory["pods"]}
    dispatcher = hosts["dispatcher"].pod
    peers = [hosts[role].pod for role in ROLES[1:]]
    origin = dispatcher["console_url"].rstrip("/")
    runtime = {"run_id": inventory["run_id"], "expires_at": inventory["expires_at"],
               "api_url": origin + "/api", "console_url": origin + "/console/",
               "login_url": origin + "/demo-login", "account_key_file": str(state / "account-key"),
               "phase": "installing", "executors": [], "preflight": []}
    previous = state / "runtime.json"
    if previous.exists():
        existing = json.loads(previous.read_text())
        require(existing["run_id"] == runtime["run_id"], "runtime belongs to another run")
        runtime.update(existing)
    completed = runtime.get("preflight_passed") and len(runtime["executors"]) == 5
    runtime["phase"] = "checking-listeners" if completed else "installing"
    runtime["listener_checks_passed"] = False
    save(previous, runtime)

    def install(host):
        host.command("umask 077; mkdir -p " + str(BASE / "package"))
        host.copy(Path(__file__).resolve(), BASE / "bootstrap.py")
        for name, (source, _) in files.items():
            if name != "console.tar.gz" or host.pod["role"] == "dispatcher":
                host.copy(source, BASE / "package" / name)
        return host.remote("setup", {"pod": host.pod, "package": inventory["package"],
                                      "run_id": inventory["run_id"]}, timeout=720)

    if completed:
        hosts["dispatcher"].copy(Path(__file__).resolve(), BASE / "bootstrap.py")
    else:
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(install, hosts.values()))
    api = API(runtime["api_url"])
    for attempt in range(30):
        try:
            api.call("GET", "/readyz")
            break
        except (OSError, ValueError, RuntimeError):
            if attempt == 29:
                raise RuntimeError("dispatcher did not become ready") from None
            time.sleep(2)

    if not runtime.get("preflight_passed"):
        token = secrets.token_hex(24)
        try:
            for pod in peers:
                hosts[pod["role"]].remote("probe-start", {"pod": pod, "token": token,
                                                          "expires_at": inventory["expires_at"]})
            observations = []
            for pod in peers:
                observations += hosts[pod["role"]].remote("probe-client", {"pod": pod, "peers": peers, "token": token})
                runtime["preflight"] = observations
                save(previous, runtime)
            validate_preflight(peers, observations)
        finally:
            failures = []
            for pod in peers:
                try:
                    hosts[pod["role"]].remote("probe-stop", {})
                except Exception:
                    failures.append(pod["role"])
            require(not failures, "could not stop all owned peer probes; do not start guests")
        runtime["preflight_passed"] = True
        runtime["phase"] = "enrolling"
        save(previous, runtime)

    account_path = state / "account.json"
    pending_account = state / "account-create-pending.json"
    if not account_path.exists():
        require(not pending_account.exists(), "account registration outcome uncertain; inspect before retrying")
        save(pending_account, {"run_id": inventory["run_id"]})
        account = api.call("PUT", "/user", {"name": "Delivery demo " + inventory["run_id"]})
        require(account.get("role") == "user" and account.get("account_key") and account.get("recovery_code"),
                "registration did not return ordinary account credentials")
        save(account_path, account)
        pending_account.unlink()
    account = json.loads(account_path.read_text())
    save(state / "account-key", account["account_key"] + "\n")
    api.token = api.call("POST", "/auth/login", {"account_key": account["account_key"]})["token"]
    try:
        results = []
        for pod in peers:
            enrollment_path = state / (pod["role"] + "-enrollment.json")
            pending = state / (pod["role"] + "-create-pending.json")
            if not enrollment_path.exists():
                require(not pending.exists(), "executor creation outcome uncertain; inspect owned inventory before retrying")
                save(pending, {"name": pod["role"], "run_id": inventory["run_id"]})
                enrollment = api.call("POST", "/operator/executors", {"name": pod["role"]})
                save(enrollment_path, enrollment)
                pending.unlink()
            enrollment = json.loads(enrollment_path.read_text())
            if completed:
                result = next(item for item in runtime["executors"] if item["role"] == pod["role"])
            else:
                result = hosts[pod["role"]].remote("join", {"enrollment": enrollment, "pod": pod,
                                                            "peers": peers, "api_url": runtime["api_url"],
                                                            "version": inventory["package"]["version"]})
            require(result["executor_id"] == enrollment["executor"]["id"], "returned enrollment identity differs")
            results.append(result)
            if not completed:
                runtime["executors"] = results
                save(previous, runtime)
        listener_config(dispatcher, peers, results)
        applied = hosts["dispatcher"].remote("configure-listeners", {
            "pod": dispatcher, "package": inventory["package"], "run_id": inventory["run_id"],
            "peers": peers, "executors": results})
        runtime["listener_config_sha256"] = applied["sha256"]
        runtime["phase"] = "checking-listeners"
        save(previous, runtime)
        expected = {item["executor_id"] for item in results}
        for attempt in range(45):
            checks = None
            try:
                owned = api.call("GET", "/operator/executors")["executors"]
                ready = {item["id"] for item in owned if item.get("ready") and item.get("status") == "online"}
                if expected <= ready:
                    checks = fresh_listener_checks(api.call("GET", "/executors"), expected, time.time())
            except (OSError, ValueError, RuntimeError):
                pass  # The dispatcher and its control connections reconnect after restart.
            if checks:
                break
            if attempt == 44:
                raise RuntimeError("not all five owned executors have fresh dispatcher-observed TCP listener reachability")
            time.sleep(2)
        runtime["executor_ids"] = [item["executor_id"] for item in results]
        runtime["listener_checks"] = checks
        runtime["listener_checks_passed"] = True
        runtime["phase"] = "ready"
        runtime["ready_at"] = datetime.now(timezone.utc).isoformat()
        save(previous, runtime)
    finally:
        api.call("POST", "/auth/logout")
    return runtime


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--state", type=Path)
    group.add_argument("--remote", choices=("setup", "probe-start", "probe-client", "probe-stop", "join", "configure-listeners"), help=argparse.SUPPRESS)
    group.add_argument("--probe-server", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    try:
        if arguments.probe_server:
            probe_server()
            return
        if arguments.remote:
            action = globals()["remote_" + arguments.remote.replace("-", "_")]
            result = action(json.load(sys.stdin))
        else:
            result = bootstrap(arguments.state)
        print(json.dumps(result))
    except Exception as error:
        message = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        print("Bootstrap failed: " + message, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
