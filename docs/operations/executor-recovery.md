# Executor recovery

An executor keeps accepted work and completed results in local SQLite state. A restart preserves its identity and retained terminal results, but it does not resume work that was active when the control session ended.

Each run belongs to the dispatcher session that accepted it. After a reconnect, unfinished rows from an older session are quarantined rather than replayed. This prevents an old session from gaining authority after the executor reconnects.

## Operator response

1. Restore the executor service and verify that it becomes ready in the dispatcher.
2. Inspect executor logs and the dispatcher run state for work that was active during the interruption.
3. Treat an uncertain or interrupted measurement as needing an explicit decision by its owner; do not assume cancellation or completion.
4. Keep the executor database while investigating. Back it up before manual repair or a version change.

Use the [Operating an Executor Wiki page](https://github.com/netsec-ethz/debuglet/wiki/Operating-an-Executor) for routine maintenance and the [Deployment and Upgrades guide](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades) for upgrade procedures.
