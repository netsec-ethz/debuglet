# Go client example

This program uses the public `pkg/client` library to submit a compiled debuglet and print its output. It defaults to the loopback dispatcher started by `dbl up`.

```sh
dbl up
make wasm SAMPLE_DIR=examples/debuglets/go/hello-local
go run ./examples/client --wasm examples/debuglets/go/hello-local/debuglet.wasm
```

Pass `--endpoint`, `--executor`, `--allow`, and `--register` for a managed dispatcher. The example deliberately does not retain credentials; an application should store account keys and sessions with owner-only permissions. See the [Go client library guide](../../docs/client.md).
