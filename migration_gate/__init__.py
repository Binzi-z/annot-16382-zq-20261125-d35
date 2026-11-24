"""Offline cross-organization migration gate.

Standard library only, Python 3.12 on Windows.

The package implements an event-sourced migration gate for an outsourced worker
moving between tenants (organizations).  Every control record is written to an
append-only durable log and receives its authoritative sequence number only
when it is physically appended.  Validity of old-organization revocation,
migration confirmation and new-organization posting is decided by replaying
those *on-disk* sequence numbers.

Modules
-------
model     : shared vocabulary / dataclasses / decision evidence
durable   : hash-chained JSONL durable log (file + in-memory sink)
topology  : organizations, actual controllers, resources, delegation edges
engine    : the migration gate (fold / replay / authorize / recovery)
oracle    : independent reference semantics used for differential checks
exhaustive: exhaustive enumeration of short event sequences
concurrency: two worker threads + barrier proof
synthetic : 60k+ multi-organization event generator and blast-radius check
"""

__version__ = "1.0.0"
