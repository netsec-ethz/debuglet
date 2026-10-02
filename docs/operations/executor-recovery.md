# Executor recovery

An executor keeps accepted work and completed results in local SQLite state. A restart preserves its identity and retained terminal results, but it does not resume work that was active when the control session ended.

Each run belongs to the dispatcher session that accepted it. After a reconnect, unfinished rows from an older session are quarantined rather than replayed. This prevents an old session from gaining authority after the executor reconnects.

## Operator response

1. Restore the executor service and verify that it becomes ready in the dispatcher.
2. Inspect executor logs and the dispatcher run state for work that was active during the interruption.
3. Treat an uncertain or interrupted measurement as needing an explicit decision by its owner; do not assume cancellation or completion.
4. Keep the executor database while investigating. Back it up before manual repair or a version change.

Use the [Operating an Executor Wiki page](https://github.com/netsec-ethz/debuglet/wiki/Operating-an-Executor) for routine maintenance and the [Deployment and Upgrades guide](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades) for upgrade procedures.

## Archive one interrupted run locally

A stopped managed executor can keep prior-session work indefinitely. An
administrator may explicitly archive one run after investigating it, releasing
its **local execution queue admission charge** without changing its outcome.
Back up the executor state first, then drain the managed instance successfully:

```sh
sudo dbl drain --role executor --name worker
sudo dbl service archive-run --name worker RUN_UUID
sudo dbl service archive-run --name worker --apply --reason incident-42 RUN_UUID
sudo dbl drain --role executor --name worker --resume
```

The second command is a dry run. The third records a dated, immutable local
operator decision; use a short private incident reference rather than secrets.
Repeating the same run and reason is safe; a different reason is refused.
A running, enabled, failed-to-stop or modified service is refused, as is a
staged `--root`. The command holds exclusive database ownership and rechecks
successful shutdown before writing. It never stops or resumes the service for
you. Unmanaged foreground executors are not supported by this command.

The original execution row, binding, start marker, terminal result and output
remain available for inspection. They are excluded from restart, delivery and
output reconciliation; an archived identity cannot be submitted again. Inspect
it with `archive-run` without `--apply`; drain summaries count archived runs
separately. Actual bytes still occupy disk, and retained output still consumes
its spool limits. This does not release dispatcher account quotas, establish a
remote terminal result, prove what an interrupted measurement did, or change
payment records. Any fresh measurement needs its own authorized submission.

This operation requires executor schema 7. Upgrade a stopped, backed-up database
with the installed executor's `-upgrade-database` command before use; this
migration only adds the disposition record and does not discard retained work.
