# Python debuglets — not currently supported

Python debuglets are **not runnable on the current executor.** The source in
`helloworld/main.py` is kept as a reference for if/when that changes, but it
cannot be built into a working `debuglet.wasm` today. Here is why, concretely.

The executor runs guests on [wazero](https://github.com/tetratelabs/wazero) as
**WASI preview 1 core modules**, with **no filesystem mounted** and **no
component-model support**. None of the practical Python→WASM paths fit:

1. **Official CPython WASI build (`python.wasm`)** — this *is* pure
   `wasi_snapshot_preview1` and runs on wazero, but it loads your script and the
   standard library from a **preopened directory**. The executor configures no
   filesystem (`debuglet.go` sets stdout/stderr/clocks/argv only), so the
   interpreter has nothing to run.

2. **`py2wasm` (Wasmer, Nuitka-based)** — produces a self-contained module that
   needs no filesystem, but it (a) supports only Python ≤3.11 and crashes on
   newer interpreters, and (b) targets Wasmer's **`wasix`** runtime extensions,
   which wazero (pure WASI p1) does not implement, so the output won't
   instantiate on the executor.

3. **`componentize-py`** — emits a **wasip2 component**, and wazero does not
   support the component model.

Making Python work would require either teaching the executor to preopen a
directory containing `python.wasm` + the script (option 1), or a wasip1-only,
filesystem-free Python toolchain that does not yet exist in a form wazero can
run. Until then, use **Go**, **Rust**, or **C** (see [../README.md](../README.md)).
