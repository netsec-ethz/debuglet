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

Each guest prints one line. Every module was built in a pinned container and
run five times (three for Python with a filesystem) by a small runner that uses
wazero v1.12.0 with the executor's runtime and module configuration (the same
interpreter, memory limit and module options as
`internal/executor/debuglet/debuglet.go`, without the `env` host module, which
none of these hello guests imports). Peak resident memory is the runner
process's maximum RSS as reported by `/usr/bin/time -v`; the runner alone with
an empty module uses 6 MiB. Times are medians on one x86-64 Linux build host,
limited to three CPUs; treat them as orders of magnitude.

| Language | Toolchain | Build command | Module size | Build time | Engine compile | Start to first output | Peak RSS | Host operations available |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Go | Go 1.26.8 | `GOOS=wasip1 GOARCH=wasm go build -trimpath` (`examples/debuglets/go/hello-local`) | 2,600,518 B | 3.8 s cold cache, 0.04 s warm | 116 ms | 14 ms | 69 MiB | All of ABI v1 and `debuglet_io_v1` through `pkg/debuglet`; arguments and output |
| Rust | rustc 1.90.0, `wasm32-wasip1` | `cargo build --release --target wasm32-wasip1` (`examples/debuglets/rust/helloworld`) | 65,127 B | 0.2 s | 3 ms | 0.6 ms | 9.3 MiB | TCP, TLS, listener and ICMPv4 through the experimental crate; arguments and output |
| C | wasi-sdk 25 (clang 19.1.5) | `clang -O2 main.c -lm` (`examples/debuglets/c/helloworld`) | 50,067 B | 0.07 s | 0.8 ms | 0.1 ms | 7.0 MiB | TCP, TLS, listener and ICMPv4 through the experimental header; arguments and output |
| JavaScript | Javy 9.1.0 (static module, QuickJS embedded) | `javy build -o hello.wasm hello.js` | 1,358,167 B | 4.9 s | 73 ms | 1.4 ms | 45 MiB | Output only: no `env` imports and no arguments |
| Python | CPython 3.14.7 WASI build (wasi-sdk 24), debug sections stripped | none (prebuilt interpreter, script passed with `-c`) | 7,630,023 B (30,522,756 B as released) | none | 255 ms | fails at startup | 158 MiB until the failure | None on the engine; see below |

Python with its standard library mounted read-only, which the engine does not
offer, printed its line after 1.5 s at a peak RSS of 212 MiB.

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
  part of the ABI and no CI lane builds them. Promoting either would need the
  missing bindings (UDP, address getters, `drain_connection`,
  `debuglet_io_v1`), a CI build with the pinned toolchain and an owner.
- **JavaScript: unsupported.** A guest can print but cannot take arguments or
  measure anything. Supporting it would mean maintaining a Javy plugin that
  exposes the ABI, an argument channel, a pinned Javy release and a CI lane.
- **Python: unsupported.** It does not start on the engine. Supporting it would
  mean maintaining a custom CPython WASI build with an embedded standard
  library and an ABI extension module, and accepting its start-up cost.

No runtime, build path or CI lane for JavaScript or Python is part of the
repository.
