# Local environment checks

`make ci-compatibility` and `make ci-local` verify an installed Debuglet package on Linux amd64. They start temporary loopback roles, submit a TEST debuglet, check output and terminal state, and clean up.

These checks are for package validation. They do not test remote topology, production credentials, external identity providers, or a real payment system.

Run the standard workflow instead of invoking the internal checker directly:

```sh
make ci-build
make ci-package
make ci-compatibility
make ci-local
```

The test evidence is written below `.cache/ci/`. See [CI](ci.md) for the full validation matrix.
