# Managed role services

`dbl service install` writes a unit like the two in this directory, one per
installed role instance, and then owns exactly that unit. The files here are
reference copies for a version `0.0.0-reference` package installed under
`/usr/local`: the renderer in `internal/demo/service` produces them byte for
byte, and a test in that package compares its output against these files, so a
change to the generated unit cannot land without updating this reference.

They are not deployed by anything. The profile, the paths, what the unit states
and why, and the drain semantics are described in
[Managed services](../../docs/services.md).
