# Generated code

Keep generated files in the same pull request as the definition that produced them.

```sh
make proto          # protocol Go bindings
make generate-sql   # SQL query bindings
bash scripts/ci-generate.sh check
```

`protocol/protocol.proto` is the source for control-protocol bindings. SQL queries and migrations under `internal/*/database` are the source for database bindings. Generator versions are pinned in [`mise.toml`](../../mise.toml) and the generation script.

`check` regenerates into a temporary directory and fails on drift without changing tracked files. Run it before review whenever a protocol, query, migration, or generator pin changes. eBPF source changes also need their generated artifacts and applicable kernel checks.

The kernel lane first loads and tests the committed eBPF objects, then regenerates
both `*_bpfel.o` and `*_bpfel.go` files and fails if any bytes differ. Build the
image pinned by `deploy/ci/images.env`, use its compiler/headers with the module's
pinned `bpf2go`, and include the generated files in the same change as C source or
generator updates. Regenerating with a different local compiler is not the
canonical baseline. Both before/after hashes, the drift diff and the independent
kernel-load test results are retained in CI evidence; generation drift does not
by itself show a traffic-policy failure.
