# aster_acme_process

`aster_acme_process` is the shared process-lifecycle boundary for commands
started by AsterACME. The deploy reload executor and external DNS adapter use
the same ownership, deadline, cancellation, and output-draining implementation.

## Process contract

`ProcessSpec` supplies an executable path, exact argv values, optional stdin,
deadline, stdout/stderr retention limits, and an environment policy. Commands
are executed directly; no shell string parsing occurs. The caller may clear
inherited variables and add only explicit environment values.

The runner captures stdout and stderr concurrently, continues draining after
the retention limit, and reports truncation. A callback can stream
retained chunks to a caller-owned renderer. The runner owns a Unix process group or
Windows Job Object, terminates owned descendants when the leader exits, and
also stops/reaps the tree under a bounded shutdown on cancellation or timeout.
Dropping the future starts process-tree termination as a last-resort guard;
normal callers await the cancellation path before releasing business leases.

The runner does not classify business outcomes. Deploy reload maps uncertain
completion to its saved reload state and controls retries. ADPP validates JSON,
maps child failures to provider diagnostics, and retains uncertainty for any
publication that may have reached the child. Stdin is never included in
captured output or diagnostics.

The module is internal to this workspace. The deploy reload regression suite
and process-specific tests define its supported platform behavior.
