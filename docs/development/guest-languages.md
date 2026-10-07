# Guest languages

A debuglet is any WebAssembly module that targets `wasm32-wasip1` and imports
only WASI and the functions of guest ABI `debuglet-go-wasi-imports-v1`
(optionally `debuglet_io_v1`). The executor runs it in wazero's interpreter
with a 256 MiB memory limit, standard output and error, clocks, sleep, random
bytes and the job's arguments. It provides no filesystem, no environment
variables and no standard input. An uploaded module is at most 24 MiB.

This page records how a hello-world guest in each candidate language fares
under those conditions. It is a measurement, not a support commitment.

## Measurements

Each guest prints one line. The retained Rust/C figures below are from the
initial toolchain assessment. The Go, JavaScript and Python rows were reproduced
with the checked-in runner and inputs on x86-64 Linux. Times are medians of five
fresh processes (three for the Python filesystem comparison), not performance
thresholds. Peak RSS includes the runner process and compilation; it is not the
guest's linear memory. The runner uses the executor's wazero interpreter,
256 MiB memory limit, clocks and randomness, without networking host modules.
It records compilation separately from time to first stdout and stderr, so
Python's startup error is never counted as successful first output.

| Language | Toolchain | Module size | Build time | Engine compile | First stdout | Peak RSS | Host operations available |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Go | Go 1.26.8 | 2,600,518 B | 3.39 s cold, 0.036 s warm | 86 ms | 10 ms | 71 MiB | ABI v1 and `debuglet_io_v1` through `pkg/debuglet`; arguments and output |
| Rust | rustc 1.90.0, `wasm32-wasip1` | 65,127 B | 0.2 s | 3 ms | 0.6 ms | 9.3 MiB | Experimental TCP, TLS, listener and ICMPv4 bindings; arguments and output |
| C | wasi-sdk 25 (clang 19.1.5) | 50,067 B | 0.07 s | 0.8 ms | 0.1 ms | 7.0 MiB | Experimental TCP, TLS, listener and ICMPv4 bindings; arguments and output |
| JavaScript | Javy 9.1.0 static module | 1,358,212 B | 2.19 s | 60 ms | 1.2 ms | 47 MiB | Output only; no `env` imports or argument channel |
| Python | CPython 3.14.7 WASI build, stripped | 7,630,023 B | Prebuilt interpreter | 227 ms | Startup fails | 170 MiB | None on the engine |

The Python module is 30,522,756 bytes before stripping. With its standard
library mounted read-only, which the executor does not offer, it prints after
1.31 s at 203 MiB peak RSS. These are measurements, not a support commitment.

## Reproduce the measurements

On Linux amd64 with Docker, curl, gzip, `sha256sum` and Python 3:

```sh
bash scripts/measure-guest-languages.sh
```

The script keeps JSON samples, build times, toolchain versions and module
SHA-256 hashes under `.cache/guest-measure/`. It builds
`tools/guest-measure`, Go's `examples/debuglets/go/hello-local`, and the retained
`examples/debuglets/javascript/hello.js`; Python runs
`python -c "print('Hello from Debuglet! (Python)')"`. It checks the expected
missing-`encodings` startup failure without a filesystem, then runs the separate
filesystem diagnostic. The runner has a 30-second deadline and bounded output.
Go runs in the digest-pinned image in `deploy/ci/images.env` with three CPUs and
5 GiB RAM; the script records the actual Go and wazero versions. Javy runs as a
native Linux executable. Rust/C hello figures above used `cargo build --release
--target wasm32-wasip1` in `examples/debuglets/rust/helloworld` and wasi-sdk 25
`clang -O2 main.c -lm` in `examples/debuglets/c/helloworld`.

The download script checks these exact archives before extraction:

| Input | SHA-256 |
| --- | --- |
| [Javy 9.1.0 Linux amd64 gzip](https://github.com/bytecodealliance/javy/releases/download/v9.1.0/javy-x86_64-linux-v9.1.0.gz) | `a68b122d48eb3dfc1b801d4e14c39271fde3638243d3272d206e376ac9189e39` |
| [CPython 3.14.7 wasi-sdk 24 zip](https://github.com/brettcannon/cpython-wasi-build/releases/download/v3.14.7/python-3.14.7-wasi_sdk-24.zip) | `2e064d3fb8172471d39d741348efa722349c40b96301f69968dff714999c584b` |

The Python archive is Brett Cannon's experimental WASI build, not an official
CPython release artifact. Stripping uses `llvm-strip --strip-all` from wasi-sdk
25 pinned in the script. The measured modules have hashes:

- Go: `bcdf89c2102c404ab40091acef44ff00fbd5dd6e77f3bdd64b09caff3b5b3f8a`.
- JavaScript: `853baf0024ebbe9aa40784b69e45cd296e68b2c620d0a26386d9e0f90e901ba8`.
- Python: `7fe2dead89e0f64016c79142c0badd45e95b66808fc30ea904d149deda92b8a0`.

## Rust and C source and consumer checks

```sh
bash scripts/ci-guest-languages.sh
```

The `guest-languages` CI job runs this same script. It rebuilds the retained
TCP fixtures with digest-pinned Rust 1.90 and wasi-sdk 25 images, requires exact
binary equality, and checks source hashes in their `.wasm.json` records. It
also packages the Rust crate with its license, copies the C header and license,
and builds consumers in empty directories from those deliverables. Both fresh
consumers run against the current executor host for a TCP read larger than the
ABI buffer followed by EOF, listener echo, and connection-refusal behavior.
Artifacts include the source packages, consumer modules, SHA-256 manifest and
JSON test results under `.cache/guest-languages/`.

This validates local source packaging and the tested TCP subset. It does not
publish a crate or release, cover every binding, or establish a maintainer and
support policy. Changing a binding requires deliberately rebuilding and
updating the retained module's source and binary record together; a stale
fixture fails the checks.

## JavaScript

Javy compiles JavaScript into a module that embeds the QuickJS engine and
imports only WASI, so the engine links and runs it. Its dynamic mode, which
produces a small module importing a separate QuickJS plugin module, cannot run:
the engine links no such module.

The JavaScript program can write output and nothing else that matters here.
Javy 9.1.0 exposes `console` and `Javy.IO.readSync`/`writeSync` on file
descriptors, but no argument list, and the engine provides no standard input,
so a guest cannot receive its arguments. Javy offers no way for JavaScript to
call the `env` imports. Reaching them would need a custom Javy plugin written
in Rust that exposes the ABI to JavaScript, built and maintained against
Javy's plugin interface, which has changed across major releases.

## Python

The CPython WASI build needs its standard library (10 MB in the release) from
a filesystem: on the engine it stops with `Fatal Python error: Failed to import
encodings module` and exit code 1 before running any user code. The released
`python.wasm` is also larger than the 24 MiB module limit until its debug
sections are stripped. A runnable Python guest would need the standard library
embedded into the module (for example with a virtual filesystem linked into
the interpreter), a custom interpreter build with a C extension module that
exposes the `env` imports, since CPython on WASI has no other way to call
them, and acceptance of a 1.5 s, 200 MiB start for every job.
`componentize-py` produces WebAssembly components, which the engine does not
run.

## Proposal

The maintainers decide; this is the proposal the measurements support.

- **Go: supported.** It is the only language with the complete host interface,
  and the repository builds and tests it.
- **Rust and C: experimental.** They are small and fast, and the test suite
  runs one retained guest per language on the engine, but their bindings cover
  part of the ABI. CI rebuilds their sources and tests fresh package consumers.
  Promoting either still needs the missing bindings (UDP, address getters,
  `drain_connection`, `debuglet_io_v1`), a release/distribution decision and an
  accountable owner accepting the support policy.
- **JavaScript: unsupported.** A guest can print but cannot take arguments or
  measure anything. Supporting it would mean maintaining a Javy plugin that
  exposes the ABI, an argument channel, a pinned Javy release and a CI lane.
- **Python: unsupported.** It does not start on the engine. Supporting it would
  mean maintaining a custom CPython WASI build with an embedded standard
  library and an ABI extension module, and accepting its start-up cost.

The JavaScript/Python scripts are reproducible assessment tools, not supported
SDKs or executor runtime additions. No maintainer support decision is implied
by these measurements.
