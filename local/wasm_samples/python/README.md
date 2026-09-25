# Python example

Python guests are not supported by the current executor. `helloworld/main.py` is source-only; this repository provides no Python build target that produces a runnable guest.

The executor accepts WASI preview1 core modules, supplies no guest filesystem, and does not run WASI components. A Python interpreter/toolchain would have to fit those requirements before this example could be submitted.

**Unsupported.** There is no build path here, so there is nothing to submit and
nothing this repository can check.

Use the [Go guest SDK](../go/README.md) for supported measurements. The other
experimental language examples are listed in the [shared guide](../README.md),
and the supported set is in the [guest guide](../../../docs/GUESTS.md).
