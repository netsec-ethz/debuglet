# JavaScript sample

`helloworld` prints a greeting with `console.log`. It is compiled with [Javy](https://github.com/bytecodealliance/javy), which embeds a JavaScript engine in a WASI module.

**Experimental. Not a supported quickstart.** The JavaScript example is
stdout-only, and nothing in this repository builds, executes or checks it. This
repository provides no JavaScript bindings to the executor's custom network
imports. Use the [Go samples](../go/README.md) for supported measurements.

Install Javy, then build from the repository root:

```sh
make wasm SAMPLE_DIR=local/wasm_samples/javascript/helloworld JAVY=/path/to/javy
```

If `javy` is already on `PATH`, omit the override. Submit the resulting file to an existing dispatcher/executor:

```sh
dbl run --wasm local/wasm_samples/javascript/helloworld/debuglet.wasm \
  --executor EXECUTOR_ID --wait
```

Replace the ID with one returned by `dbl nodes`. See the [shared guide](../README.md) for the WASI argument and output model. Building the module alone does not verify its runtime compatibility.
