# Run the delivery experiment on Runpod

This example launches six temporary CPU pods: one dispatcher and console, plus
five enrolled executors. It uses real TCP connections between the executors and
the ordinary Debuglet account, enrollment, and measurement APIs. No GPU, external
identity provider, wallet, or payment activation is required.

Use an always-on Linux controller with systemd, sudo, Python 3.11 or later,
OpenSSH, and a Runpod account with an API key and existing credit. The controller
must stay online until cleanup is confirmed. The expiry service survives a
terminal disconnect and controller reboot; it cannot delete pods while the
controller or Runpod API is unreachable. The four-hour estimate is bounded to
$10 before creation, not a provider-enforced billing cap.

Prepare these artifacts on your build host or CI, then copy them to the
controller. The pods do not build Go or the console:

- A full Linux amd64 Debuglet package, its `install.sh`, and matching
  `SHA256SUMS` from the same build. A CLI-only package is insufficient.
- A gzip tar archive of the matching console build, including the delivery
  experiment template. Build the console with `VITE_BASE_PATH=/console`.
  The archive may contain `index.html` at its root or `console/index.html`.
- The expected SHA-256 digest of each archive, obtained from the build output.
  Use an explicit version and exact artifacts, not a moving download URL.

## Plan, arm cleanup, and launch

The following commands run on the controller from this directory. Substitute
your artifact paths, version, and published build hashes. Choose a new absolute
state directory without spaces; it holds credentials and must remain private.
Keep the API key out of shell history and logs.

```sh
read -r -s -p 'Runpod API key: ' RUNPOD_API_KEY; echo
export RUNPOD_API_KEY
DEMO_STATE="$HOME/debuglet-demo-state"

python3 demo.py --state "$DEMO_STATE" plan \
  --package-dir /absolute/path/to/package \
  --version v0.0.0-demo \
  --archive-sha256 EXPECTED_FULL_PACKAGE_SHA256 \
  --console-archive /absolute/path/to/console.tar.gz \
  --console-sha256 EXPECTED_CONSOLE_SHA256

sudo --preserve-env=RUNPOD_API_KEY python3 demo.py --state "$DEMO_STATE" arm
python3 demo.py --state "$DEMO_STATE" up
python3 demo.py --state "$DEMO_STATE" bootstrap
```

`plan` only reads Runpod pricing and inventory, verifies local artifacts, and
saves the plan. The default regions, in dispatcher then executor order, are
`EU-RO-1,EU-CZ-1,EU-NL-1,US-CA-2,US-GA-2,US-NC-2`. Override them with
`--regions` and exactly six comma-separated entries if capacity is unavailable.
The default CPU flavor is `cpu3c`, with two vCPUs per pod. Pricing includes all
six pods, 35 GB of container disk, and a 25% reserve. `--hours` may shorten the
four-hour lifetime and `--budget` may lower the $10 limit. Expiry starts at
planning and cannot be extended by rearming the guard.

`arm` installs an independently running system service before the first paid
request. Wait briefly and repeat `up` if it reports that the first healthy guard
heartbeat has not arrived. `up` checks pricing again and issues one create
request for each role. It saves each attempt before sending it. If a create
response is lost, it stops; `status` and the guard reconcile the full unique
name against the account inventory. Never delete the state or manually repeat
an uncertain create request. Once an uncertain role is found, `up` can continue
the remaining roles without recreating existing ones.

If sudo is unavailable, the controller's always-on Docker daemon can run the
same guard. Supply an **existing local** image ID or repository digest containing
`/usr/bin/python3` (3.11+) and trusted CA certificates. Run as the state directory
owner; no image is pulled and an existing container with the same name is refused:

```sh
python3 demo.py --state "$DEMO_STATE" arm --docker-image sha256:EXISTING_LOCAL_IMAGE_ID
```

The guard container restarts unless explicitly stopped, drops all capabilities,
has a read-only root and a writable temporary directory, and mounts only this
private state directory. It does not receive the Docker socket. Keep the daemon
running until cleanup completes; afterwards remove the named guard container.
Use either guard installation method for a plan, not both.

`bootstrap` verifies and installs the selected artifacts through SSH with host
keys obtained from authenticated Runpod logs. It creates a temporary TLS CA,
ordinary account, and five enrolled identities. Daemons run as an unprivileged
user under a supervisor; the public console proxies the native TLS API on the
same origin. Account keys, recovery credentials, SSH keys, and enrollment state
remain in private files, not the console archive or command output.

## Open the console

After bootstrap, read `runtime.json` in the state directory. Open its
`login_url`, paste the value from the private `account-key` file, and sign in.
This uses the existing account-key login endpoint and normal secure session
and CSRF cookies. The page contains no embedded credentials. It redirects to
the console; select the delivery experiment and the five executor IDs listed
in `runtime.json`.

The console archive must use same-origin `/api` and `/ws-api` endpoints. The
returned public URL uses Runpod's HTTPS proxy. Native executor control uses
the enrolled certificate and the demo CA, with public TCP port mappings.
Payments use the existing TEST mode; no real payment backend is configured.

## Network and fault scope

[Runpod public pod ports support TCP, not UDP](https://docs.runpod.io/pods/configuration/expose-ports).
This launcher requests a symmetric TCP mapping for each executor using the
documented `70000/tcp` allocation form, then reads the actual port before
configuring Debuglet. It does not rely on global networking, a VPN, a packet
proxy, or privileged traffic shaping.

Before enrollment, bootstrap checks all 20 directed peer connections and
records their observed source addresses. Each source must match that peer's
advertised global IPv4 address. The guest policy permits only the five selected
peer addresses and their TCP ports, with inbound connections enabled and local
targets disabled. A remapping or source-address mismatch stops bootstrap;
the example does not weaken the policy to accommodate it.

The optional fault is a **simulated connection failure inside the guest**:
messages on one directed role pair are suppressed before TCP dial/write. Other
traffic still uses real TCP. This is not injected packet loss or evidence of an
ISP outage. Write the next trial's setting with:

```sh
python3 demo.py --state "$DEMO_STATE" fault --from-role 0 --to-role 2
python3 demo.py --state "$DEMO_STATE" fault  # restore healthy settings
```

`fault` only writes `fault.json` and prints the guest arguments. Apply those
same arguments to every participant in both algorithm trials, or select the
equivalent control in the console. It does not change a running measurement.
Role numbers are 0 through 4 in the measurement's ordered participant list;
they are not inferred from cloud pod names. The unprivileged fallback counter
does not provide TCP attribution tags; protocol results do not establish
per-packet attribution.

## Status and cleanup

```sh
python3 demo.py --state "$DEMO_STATE" status
python3 demo.py --state "$DEMO_STATE" down
```

`status` reports management connectivity and cloud inventory; `runtime.json`
records application bootstrap readiness. `down` marks the plan terminating and
deletes only recorded IDs whose exact unique names still match. It excludes
resources present before planning. Cleanup is complete only after Runpod
confirms every recorded pod is absent and no create remains uncertain. Inspect
`cleanup.json`; the independent guard continues retrying incomplete cleanup.
Do not rename owned pods while the guard is active. Preserve the private state
and guard service until cleanup is confirmed, then remove the service and
private credentials when no longer needed.

Export results before expiry: pod deletion removes their local state. The
controller retains the package identities, selected endpoints, preflight
observations, and cleanup record. For API outages, inspect Runpod's console and
the exact IDs in this inventory; never substitute deletion by name prefix or
whole-account cleanup.

Offline regression checks, with all cloud and host operations replaced by
fixtures:

```sh
python3 -m unittest discover -s examples/experiments/runpod -p 'test_*.py' -v
```
