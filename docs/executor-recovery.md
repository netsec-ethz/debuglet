# Executor recovery

An executor keeps its accepted work and its finished results in a local SQLite
database, so a restart or a lost control connection does not silently discard
them. This page describes what survives, what an operator can read back, and
what the current alpha still does not establish.

## Control bindings

Every accepted run records the control session that accepted it: the dispatcher
incarnation and the session identifier. That pair is immutable for the life of
the run. A reconnecting executor negotiates a new session, so rows accepted by
an earlier one are quarantined instead of replayed: they are neither started nor
deleted, and the new session cannot cancel them. The startup log reports how
many rows were quarantined and how many finished results are still unreconciled.

Rows written before control bindings existed carry an empty binding. They are
quarantined for the same reason and remain readable.

## Retained terminal results

When a run reaches a terminal result, the executor selects that result once,
writes it to local storage under the run identity and its original binding, and
only then reports it. The scheduler deletes the execution row after the report,
so the retained result outlives the run it describes.

Delivery is bounded. The executor makes at most three attempts, all inside the
same cleanup budget, and every attempt sends the identical result. Cleanup and
scheduler joins are never extended by a failing report. Retrying stops
immediately when the run's own session is revoked, expired or replaced: a report
is only ever sent under the binding that accepted the run, so an old session
gains no authority from a retry.

A refusal the dispatcher would only repeat ends delivery immediately rather than
consuming the remaining attempts. A run that belongs to another session, a run
the dispatcher does not have, and a request it rejects as invalid are all
recorded as refused: the result stays as evidence with its cause, and it leaves
the set of results a session tries to deliver, so it is never retried forever.

Retention ends when the executor observes an acknowledgement, which releases the
row. Anything still retained is unreconciled, and records the chosen exit code
and message, the run's binding, when the result was chosen, how many delivery
attempts were made, whether it was refused, and a bounded diagnostic from the
last failure. Zero attempts means the result was never sent at all. Because the
same result is resent unchanged, a duplicate that reaches a dispatcher which
already recorded the run as finished changes neither the recorded outcome nor
its payment and resource effects.

While a session is running, the executor reconciles retained results in its own
worker, which the heartbeat only asks to run and which the session joins before
it closes its transport and database. A pass carries at most 32 results and is
bounded in time; whatever it does not reach stays for the next pass. A pass
selects only the results its own session can still deliver, so results owned by
a replaced session and results already refused cannot crowd out results that
can still be delivered. Each result is delivered by one caller at a time, so a
pass and a finishing run never settle the same result together. Reconciliation
reads and sends only. It never promotes queued work, constructs a runtime or
runs a guest again.

Limits worth knowing:

- A dispatcher accepts a terminal report only from the session that owns the
  run. An executor that restarts negotiates a new session, so results retained
  from an earlier session cannot currently be redelivered. They are retained and
  readable, and reconciling them needs a dispatcher-side change.
- An acknowledgement releases the retained row. The absence of a row therefore
  means either acknowledged or never recorded; it is not by itself proof that a
  particular run finished.
- Retention is local to one executor and one state directory. Reusing state with
  a different package version is rejected.
- Refused and orphaned results are kept, not pruned. They stay readable and are
  counted at startup, but nothing removes them automatically.

## Inspecting one retained run

The control protocol has an optional point lookup, `InspectRetainedRun`, which
reads one stored run without touching it. It is admitted like every other
control effect: the caller must hold the current session and must name that same
session in the request. Executors that do not implement it answer
`UNIMPLEMENTED`, which is never an answer about a particular run.

A lookup returns one of three outcomes:

- `FOUND` with the run identity, the binding that originally accepted it, the
  transaction identifier, whether it was started, and its start marker and due
  time. The stored program and its arguments are never read.
- `FILTERED` when a row with that identity exists but belongs to the caller's
  current session. This is deliberately not an answer that the work is missing.
- `ABSENT` when no stored row carries that identity.

Everything else is an error: a malformed identity, a stored row whose
transaction identifier exceeds the 256-byte bound on the only variable-length
field of an answer, a read failure, and a shutting-down executor. None of them
is reported as a missing row.

Inspection performs no scheduling, no start, no finalization, no deletion and no
payment write, and it leaves quarantined rows exactly as they were. The reader
stays owned for the whole lookup: a caller that gives up bounds only its own
wait, and shutdown still joins the read before the database is closed.

The dispatcher does not yet expose this lookup over its client API.

## Bandwidth limits after a capacity change

An executor caches the executor-wide share and each destination share of a
running program. Each of those is invalidated on its own, by a capacity change
for that dimension and by a membership change that adds or removes a competitor.
Reading one cached share therefore never suppresses a pending recomputation of
another, and a lowered capacity is applied to programs that are already running
without waiting for another run to start. A destination share exists only for a
program whose policy declared that destination; a destination another program
declared is not readable and receives no limit.
