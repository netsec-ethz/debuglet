# Managed services

`dbl service` installs a dispatcher or executor as a system service. Use it only for a host-local, managed profile. Networked production deployments use the [Ansible deployment](../deploy/ansible) and the [operator Wiki](https://github.com/netsec-ethz/debuglet/wiki).

## Basic workflow

Install the package under a system prefix, create an unprivileged service account, then install and inspect each role:

```sh
sudo dbl service install --role dispatcher
sudo dbl service install --role executor --dispatcher 127.0.0.1:9001
sudo dbl service status --role dispatcher
sudo dbl service status --role executor
```

Use `dbl drain --role executor` before planned maintenance and `dbl drain --role executor --resume` when it is ready again. Service commands need administrator privileges.

The service owns its role-specific SQLite state and retains it across restart. A database is not automatically migrated or safe to reuse across arbitrary package versions. Back up state and follow the [Deployment and Upgrades guide](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades) before upgrading.

Reference unit files live in [`deploy/systemd`](../deploy/systemd).
