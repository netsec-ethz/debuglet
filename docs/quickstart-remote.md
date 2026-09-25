# Run a dispatcher and executors on separate hosts

The [installation guide](../README-install.md) starts both roles on one machine over loopback, which is the one shape a cleartext control channel is supported in. This guide is the other one: a dispatcher reachable over the network, terminating TLS itself against a private authority, with authentication on and payments off, and executors and clients on other machines. TEST bookkeeping still runs and no wallet is involved. Throughout, `HOST` is the address peers dial, `HTTP_PORT` the port carrying the HTTP API and the executors' reverse control stream, `GRPC_PORT` the direct gRPC port, `VERSION` the package version and `PREFIX` an installation prefix.

## What you need

- A Linux amd64 host for the dispatcher whose address `HOST` its peers can reach, and one Linux amd64 host per executor. A client needs no privilege, no daemon and no wallet.
- The three files of one package build — `debuglet-VERSION-linux-amd64.tar.gz`, `install.sh` and `SHA256SUMS`, from the same job — on every host; see the [installation guide](../README-install.md). Every role runs the same version.
- `openssl` on the dispatcher host, the one machine where this deployment's certificates are issued.

## The dispatcher

**1. Install the package.** The installer verifies both payloads before it writes anything.

```sh
sh ./install.sh --archive ./debuglet-VERSION-linux-amd64.tar.gz --checksums ./SHA256SUMS --version VERSION --prefix PREFIX
export PATH="PREFIX/bin:$PATH"
```

**2. Issue the authority and two leaf certificates.** The server certificate has to carry the address executors dial as a subject alternative name, written `DNS:HOST` where peers dial a name; a common name alone is not accepted. The client certificate is the executor's identity, which the executor daemon requires whenever TLS is on, whether or not the dispatcher verifies it. Afterwards `ca.crt` is the only file that leaves this host — it goes to every executor and every client — and `ca.key` belongs on neither daemon host, as [provisioning](environments.md#provisioning) describes.

```sh
mkdir -p /etc/debuglet/certs && cd /etc/debuglet/certs
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -subj "/CN=Debuglet CA/O=Debuglet" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -subj "/CN=dispatcher/O=Debuglet" -out server.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:HOST\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.ext
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -subj "/CN=executor/O=Debuglet" -out client.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extfile client.ext
chmod 600 ca.key server.key client.key
```

**3. Create the database.** A daemon never creates its own schema; one run of the local role does. Mode `0700` on the state directory is checked before the database is created, and port `0` keeps this run off the ports the daemon will bind. Ctrl-C once it reports ready leaves `dispatcher.sqlite` behind.

```sh
mkdir -p /var/lib/debuglet/dispatcher && chmod 700 /var/lib/debuglet/dispatcher
dbl dispatcher up --state-dir /var/lib/debuglet/dispatcher --port 0 --grpc-port 0
```

**4. Write `/etc/debuglet/dispatcher.toml`.** Omitted keys keep the defaults documented under [daemon configuration](environments.md#daemon-configuration). `local_development = false` is what makes every request that is not public need a session, and `bind_host = "0.0.0.0"` is what puts the listeners on an address other than loopback. Adding `ca_file` and `require_client_cert = true` binds each executor ID to the certificate it enrolled with.

```toml
[server]
bind_host = "0.0.0.0"
http_port = HTTP_PORT
grpc_port = GRPC_PORT
local_development = false
[tls]
disable = false
cert_file = "/etc/debuglet/certs/server.crt"
key_file = "/etc/debuglet/certs/server.key"
[database]
path = "/var/lib/debuglet/dispatcher/dispatcher.sqlite"
[sui]
disabled = true
```

**5. Start the daemon** and **6. verify `/version`** from another machine with `ca.crt` copied down. Only `dbl` is linked into `PREFIX/bin`; the daemons live beside it. Linux keeps 15 characters of a process name, so a backgrounded one is stopped with `pkill -x debuglet-dispat` rather than by its full name.

```sh
"PREFIX/lib/debuglet/VERSION/bin/debuglet-dispatcher" -config /etc/debuglet/dispatcher.toml
curl --cacert ca.crt https://HOST:HTTP_PORT/version          # from the other machine
```

## An executor on another host

Install the same package, then copy `ca.crt`, `client.crt` and `client.key` into a directory `DIR` only this user can read. Create the schema-only database the same way; `dbl up` starts a loopback pair and needs nothing else, so it works on a machine that has no dispatcher of its own.

```sh
mkdir -p DIR/state && chmod 700 DIR/state
dbl up --state-dir DIR/state --port 0                        # Ctrl-C once it reports ready
cp DIR/state/executor.sqlite DIR/executor.db && chmod 600 DIR/executor.db
```

```toml
# DIR/executor.toml
[identity]
executor_id = "UUID"                 # any UUID; keep it stable across restarts
[dispatcher]
addr = "HOST:GRPC_PORT"              # direct gRPC, where BindSession arrives
yamux_addr = "HOST:HTTP_PORT"        # the reverse control stream, beside the HTTP API
[tls]
disable = false
[credentials]
ca_cert = "DIR/ca.crt"
client_cert = "DIR/client.crt"
client_key = "DIR/client.key"
[resources]
capacity = 1000000000
[network]
packet_counter = "fallback"
disable_scion_environment = true
[database]
path = "DIR/executor.db"
[pricing]
price_per_bw_s = 1
currency = "TEST"
```

The two dispatcher addresses are not interchangeable. With both set to the HTTP port the reverse stream comes up and the dispatcher answers on it, but the direct gRPC call has nowhere to land: the dispatcher reports a failed executor registration and an unavailable control session, and the executor reconnects forever without announcing resources.

`packet_counter = "fallback"` counts in userspace and needs no privilege; `"auto"` with `interface = "NAME"` loads the eBPF counter and tagger when it has the privileges for them (root or the eBPF capabilities) and otherwise falls back to userspace counting with a warning, and a root run leaves root-owned `-wal` and `-shm` files beside whatever database it opens, so give it one of its own. Start the daemon in the foreground. Four lines and then silence is the whole story: resources announced, heartbeat running. Give it 15–30 seconds before the first client, which otherwise sees the executor listed with `READY false`.

```
$ "PREFIX/lib/debuglet/VERSION/bin/debuglet-executor" -config DIR/executor.toml
INFO	executor/node.go:99	Initialized daemon resources	{"packet_counter": "fallback", "TESLA_expiry": "..."}
INFO	executor/node.go:168	Retained quarantined executor rows	{"count": 0, "unacknowledged_exits": 0}
INFO	executor/executor.go:272	Announced resources
INFO	executor/executor.go:292	Starting heartbeat loop	{"interval": "15s"}
```

## Clients

**Linux, natively.** `pkg/client` verifies the chain against the host's trust store; on Linux `SSL_CERT_FILE` replaces that store for one process, which needs no root and installs nothing. `login --register` writes the account key and the recovery code to owner-only files beside the connections file and prints neither; keep both, as the [CLI guide](CLI.md#credentials) describes. `--allow-remote-test` is required on every submission to an endpoint that is not a literal loopback address.

```
$ export SSL_CERT_FILE=/path/to/ca.crt
$ dbl connect https://HOST:HTTP_PORT --name NAME
$ dbl login --register NAME
$ dbl nodes
$ dbl run --sample hello --wait --allow-remote-test
$ dbl logs ID
Hello from Debuglet!
dbl logs: state=RunStateExited after=1 entries=1 has_more=false
```

**macOS.** There is no native package, so a Mac runs the Linux client in a `linux/amd64` container that carries the authority in its own trust store. `docker run --rm -it --platform linux/amd64 IMAGE` then takes the five commands above unchanged and without `SSL_CERT_FILE`; on Apple Silicon the image runs under emulation, and `--rm` discards the account key, the recovery code and the session with the container.

```dockerfile
FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
COPY ca.crt /usr/local/share/ca-certificates/debuglet-ca.crt
COPY install.sh SHA256SUMS debuglet-VERSION-linux-amd64.tar.gz /pkg/
RUN update-ca-certificates && sh /pkg/install.sh --archive /pkg/debuglet-VERSION-linux-amd64.tar.gz --checksums /pkg/SHA256SUMS --version VERSION --prefix /opt/debuglet
ENV PATH=/opt/debuglet/bin:$PATH
```

**The Go SDK.** The [client example](../examples/client/main.go) takes the same three remote options: `--register NAME` creates an account and logs in for the rest of the run, `--allow-remote-test` sets `Options.AllowRemoteTEST`, and `--allow HOST[,HOST]` fills the request's address allowlist, which narrows the executor's own policy — public addresses admitted, loopback, private and reserved ranges denied — and never widens it. The account id is printed; the account key and the session token are not.

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/latency
go run -mod=readonly ./examples/client --endpoint https://HOST:HTTP_PORT --register NAME \
    --allow-remote-test --allow example.com \
    --wasm local/wasm_samples/go/latency/debuglet.wasm -- -addr example.com:80 -count 3
```

```
target=example.com:80 count=3
rtt seq=0 bytes=316 ms=4.791
rtt seq=1 bytes=316 ms=4.438
rtt seq=2 bytes=316 ms=5.196
summary samples=3 min_ms=4.438 avg_ms=4.808 max_ms=5.196
```

## What the dispatcher log shows

| Step | Lines |
| --- | --- |
| Executor connected | one `Earnings` line per 15 s heartbeat; that line is the liveness signal |
| `dbl connect` | `GET /version 200`, `GET /connection 404` — a remote profile serves no local-test metadata and `connect` succeeds anyway |
| `login --register`, `nodes` | `PUT /user 200`, `POST /auth/login 200`, `GET /executors 200` |
| A submission | `intent`, `created intent`, `PUT /payment/intent 200`, `transaction_id`, `PUT /debuglet 200` |
| `run --wait`, `logs` | one `GET /debuglet/ID/state 200` per poll, then `GET /debuglet/ID/logs?after=N&limit=100 200` |
| Executor stopped | the heartbeats stop; after `scheduler.executor_timeout` the next `nodes` lists no rows |

Every API line carries the client's source address. One pair below is worth recognising, because it says nothing about the executor, which keeps running: its cause is a client that does not trust the authority. The HTTP API and the control stream share `HTTP_PORT`, so the rejected handshake reaches the control side first, and that client itself sees `tls: failed to verify certificate: x509: certificate signed by unknown authority`.

```
[ERR] yamux: Failed to read header: remote error: tls: bad certificate
ERROR	rpc/bidi.go:321	failed to register executor	{"error": "rpc error: code = FailedPrecondition desc = control session unavailable"}
```

## Limitations

- **Automatic executor selection needs exactly one ready executor.** With two, `dbl run` and the SDK example refuse and ask for an explicit `--executor ID`; with none they fail before an intent exists.
- **An account name is a label, not an identity.** Registering the same name twice succeeds and makes two separate accounts with different ids, each with its own key and its own runs.
- **Runs are private to the account that submitted them.** `status ID` and `logs ID` from another account answer `not_found`, the same as an ID that does not exist.
- **The certificate is issued for the address dialled.** Reaching the same dispatcher by another name needs `tls.server_name` in the executor configuration, or a new certificate.
- **Neither daemon creates its database schema.** Both are given one made by a local `dbl` role, and nothing upgrades one in place: another package version means another database.
- **No attribution tags without the eBPF counter.** With `packet_counter = "fallback"` each job logs that outgoing packets carry no attribution tags; nothing else changes.
