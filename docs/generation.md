# Generated sources

Three kinds of source in this repository are written by a generator and committed alongside their inputs: the protocol bindings in `protocol/`, the dispatcher and executor database bindings in `internal/dispatcher/database/` and `internal/executor/database/`, and the eBPF objects in the executor's tagger and rate-limit packages. This document covers the first two. eBPF generation needs a Linux toolchain and is described in [CONTRIBUTING.md](../CONTRIBUTING.md).

Generator versions are pinned in [mise.toml](../mise.toml) and `scripts/ci-generate.sh` reads them from there. Two further pins live in that script rather than in `mise.toml`, because neither is a tool mise installs: the Go toolchain the pinned `sqlc` is compiled with (`sqlc_toolchain`), and the leading component of the protocol compiler version stamped into the generated headers (`7.`, see below). Both are commented where they are declared.

## Regenerate

```sh
make proto          # protocol/protocol.pb.go and protocol/protocol_grpc.pb.go
make generate-sql   # db.go, models.go and the *.sql.go query bindings
```

Both targets call `scripts/ci-generate.sh`, which fetches the pinned generators from the Go module proxy on their first use; later runs are served from the module cache. Nothing else is installed: generation needs no protocol compiler binary and no distribution packages. The equivalent direct calls are:

```sh
bash scripts/ci-generate.sh write-proto
bash scripts/ci-generate.sh write-sql
bash scripts/ci-generate.sh write        # both
```

A write mode replaces the tracked generated sources in the checkout and removes generated files the pinned generators no longer produce. It touches nothing else. The root `go:generate` directive runs `write-sql`, so `go generate ./...` takes the same pinned path.

## Check for drift

```sh
bash scripts/ci-generate.sh check
```

`check` is the default. It regenerates both sets into a temporary directory and compares them with the committed sources byte for byte. Inside the checkout it writes only under `.cache/ci/generation/`, which is ignored by git; it never touches a generated source. Any difference — a changed byte, a generated file that is missing, or one the generators no longer produce — fails the run. The full difference is written to `.cache/ci/generation/generation.diff` and the first 200 lines are printed; the list of compared files is written to `.cache/ci/generation/compared.txt` when they all match.

A generator that cannot be fetched, that reports a version other than the pinned one, or that fails, also fails the run, as does a generation that produces fewer files than this repository has. There is no mode that accepts a difference or commits one on your behalf.

`check` then runs the schema checks in `internal/schemacheck` and writes their results to `.cache/ci/generation/schema-tests.json`. Both results are reported even when the comparison already failed, so one run says everything that is wrong. The same tests also run as part of `make ci-test`.

## Protocol bindings

`protocol/protocol.proto` is the canonical definition. The generated Go sources record the versions that produced them:

```
// 	protoc-gen-go v1.36.11
// 	protoc        v7.34.0
```

`scripts/ci-generate.sh` compiles the definition to a descriptor set, then hands that descriptor set to the pinned `protoc-gen-go` and `protoc-gen-go-grpc` in the same code generator request a protocol compiler would send, including the compiler version above. `internal/protogen` performs that step. The output is byte-for-byte what the pinned protocol compiler and plugins produce, which is what makes the comparison meaningful without installing the compiler. The generator parameters match the ones the committed sources were produced with: `paths=source_relative,Mschema.proto=.`.

The reported compiler version is derived from the `protoc` pin in `mise.toml` by prefixing it with the leading component that release reports: the release numbered 34.0 reports itself as 7.34.0. That prefix is a constant in `scripts/ci-generate.sh` and is not derivable from the pin.

Changing the `protoc` or `buf` pin therefore needs more than regenerating. Byte identity with a real protocol compiler is an empirical result for the definition in this repository, not a guarantee of the descriptor-set route. Before committing sources regenerated under a new pin, reproduce them once with a real `protoc` of the pinned release and confirm the bytes agree; adjust the version prefix if that release reports itself differently.

## Database bindings

`sqlc.yml` names the canonical inputs for both roles: the query directory and the migration directory that serves as the schema, and the directory the bindings are written to. The generator reads its inputs from a copy of those directories, so a check leaves the checkout untouched. The copy takes each directory as it stands, so an untracked `.sql` file in one of them is generated from like any other, in a check and in a write alike.

The pinned `sqlc` release requires a newer Go than the one this project builds with, so it alone is compiled with the pinned newer toolchain named in `scripts/ci-generate.sh`, which is the one sqlc's own module names. A future sqlc that needs more than that fails the run instead of choosing a toolchain on its own. The project's own build, tests and vet are unaffected.

## Schema checks

`internal/schemacheck` reads the same canonical inputs and checks them against real, temporary SQLite databases:

- Each embedded migration sequence is named `NNNNN_lower_case.sql`, runs from version 1 without gaps or repeated numbers, and carries both goose annotations.
- The sequence compiled into the binaries is the same set of bytes the checkout holds, so a migration the embed pattern misses cannot reach the generator without also being applied at runtime.
- `sqlc.yml` addresses exactly the migration, query and output directories the two roles use.
- Both sequences apply to a fresh database, and goose records every migration.
- Every committed generated query prepares against the resulting schema, and the generated queries are exactly the ones the canonical SQL declares.
- Every table of the fresh schema has a generated model with matching columns, and every model has a table. The generator reads the migrations with its own SQL parser; this is the independent comparison against SQLite.

## Limits

These checks compare generator output with what is committed, and they exercise fresh databases only.

Models are matched to tables by column name alone. Types, column order and nullability are not compared, so a change that alters only a Go field type is caught by the byte comparison against the generator, not by the database check.

They do not review whether a protocol change stays compatible with deployed peers on the wire: adding, renumbering or retyping a field passes as soon as the generated sources are regenerated. Wire compatibility remains a review question.

They do not upgrade a database that already holds rows, and they establish nothing about the down migrations, about data preserved across an upgrade, or about an operator's existing deployment. They do not build, package or rewrite any release artifact.
