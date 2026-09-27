# Generated code

Keep generated files in the same pull request as the definition that produced them.

```sh
make proto          # protocol Go bindings
make generate-sql   # SQL query bindings
bash scripts/ci-generate.sh check
```

`protocol/protocol.proto` is the source for control-protocol bindings. SQL queries and migrations under `internal/*/database` are the source for database bindings. Generator versions are pinned in [`mise.toml`](../../mise.toml) and the generation script.

`check` regenerates into a temporary directory and fails on drift without changing tracked files. Run it before review whenever a protocol, query, migration, or generator pin changes. eBPF source changes also need their generated artifacts and applicable kernel checks.
