"""Append-only, hash-chained durable event log.

The authoritative sequence number of a record is the physical position of its
line in the log after the line has been written (and, for critical records,
``fsync``-ed).  Payload-supplied timestamps or sequence claims are ignored for
ordering: on recovery the sequence is re-derived from the lines read back from
disk and every envelope/hash is verified.

Two sinks share one implementation:

* :class:`FileDurableLog` -- real JSONL file on Windows, flush + optional
  ``os.fsync`` per append and atomic-ish recovery of a torn trailing line.
* :class:`MemoryDurableLog` -- an in-memory line store with the identical
  sequence/hash/recovery rules (used for high-volume exhaustive search).
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from .model import TamperError, canonical_json, sha256_text

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    prev: str
    hash: str
    kind: str
    payload: dict[str, Any]

    def to_line(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "prev": self.prev,
                "hash": self.hash,
                "kind": self.kind,
                "payload": self.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


def compute_hash(seq: int, prev: str, kind: str, payload: dict[str, Any]) -> str:
    body = "|".join(
        [str(seq), prev, kind, canonical_json(payload)]
    )
    return sha256_text(body)


class Sink(Protocol):
    def read_lines(self) -> list[str]: ...

    def append_line(self, line: str, sync: bool) -> None: ...

    def truncate_trailing(self, valid_line_count: int) -> None: ...

    def fsync(self) -> None: ...


class MemorySink:
    """Shared list so a "restarted" log can re-read the same durable lines."""

    def __init__(self, store: list[str] | None = None) -> None:
        self.store: list[str] = store if store is not None else []

    def read_lines(self) -> list[str]:
        return list(self.store)

    def append_line(self, line: str, sync: bool) -> None:
        self.store.append(line)

    def truncate_trailing(self, valid_line_count: int) -> None:
        del self.store[valid_line_count:]

    def fsync(self) -> None:  # nothing to do
        return None


class FileSink:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # a+ so recovery can read and later appends share one handle.
        self._f = open(path, "a+", encoding="utf-8", newline="\n")
        self._f.flush()

    def read_lines(self) -> list[str]:
        self._f.flush()
        self._f.seek(0)
        text = self._f.read()
        self._f.seek(0, os.SEEK_END)
        if not text:
            return []
        return text.split("\n")

    def append_line(self, line: str, sync: bool) -> None:
        self._f.seek(0, os.SEEK_END)
        self._f.write(line + "\n")
        self._f.flush()
        if sync:
            os.fsync(self._f.fileno())

    def fsync(self) -> None:
        self._f.flush()
        os.fsync(self._f.fileno())

    def truncate_trailing(self, valid_line_count: int) -> None:
        # Re-read valid raw lines and rewrite the file atomically enough for an
        # offline tool.  Only an invalid *trailing partial* line is removed.
        self._f.flush()
        self._f.seek(0)
        raw = self._f.read()
        lines = raw.split("\n")
        kept = lines[:valid_line_count]
        self._f.seek(0)
        self._f.truncate()
        self._f.write("\n".join(kept))
        if kept:
            self._f.write("\n")
        self._f.flush()
        os.fsync(self._f.fileno())
        self._f.seek(0, os.SEEK_END)

    def close(self) -> None:
        f = getattr(self, "_f", None)
        if f is None or f.closed:
            return
        try:
            f.flush()
            os.fsync(f.fileno())
        except (OSError, ValueError):
            pass
        finally:
            f.close()


class DurableLog:
    """Sequenced hash-chained log.  All mutation is under a re-entrant lock."""

    def __init__(self, sink: Sink, path_hint: str = "<memory>") -> None:
        self.sink = sink
        self.path_hint = path_hint
        self._lock = threading.RLock()
        self._events: list[StoredEvent] = []
        self._last_hash = GENESIS_HASH
        self._recover()

    # -- construction -------------------------------------------------------

    @classmethod
    def open_file(cls, path: str) -> "DurableLog":
        return cls(FileSink(path), path_hint=path)

    @classmethod
    def open_memory(cls, store: list[str] | None = None) -> "DurableLog":
        return cls(MemorySink(store), path_hint="<memory>")

    # -- recovery / verification -------------------------------------------

    def _recover(self) -> None:
        raw_lines = self.sink.read_lines()
        valid: list[StoredEvent] = []
        prev = GENESIS_HASH
        expected_seq = 1
        valid_raw_count = 0  # number of raw split entries that form records

        # split("\n") yields a trailing "" after the final newline.
        entries = raw_lines
        # We need raw entry accounting for truncation of a torn last record.
        record_entries = [ln for ln in entries if ln != ""]
        trailing_empty = len(entries) - len(record_entries)

        for idx, line in enumerate(record_entries):
            is_last = idx == len(record_entries) - 1
            # ---- Structural parse: only this is a plausible torn tail -----
            try:
                obj = json.loads(line)
                seq = int(obj["seq"])
                prev_h = str(obj["prev"])
                h = str(obj["hash"])
                kind = str(obj["kind"])
                payload = obj["payload"]
            except Exception:
                # Malformed JSON / missing envelope field at the physical tail
                # is a torn append: discard exactly that trailing fragment.
                if is_last:
                    break
                raise TamperError(
                    f"corrupt durable record at physical line {idx + 1}"
                )

            # ---- A complete envelope that fails verification is tampering.
            # This applies EVEN to the last record: rewriting the terminal
            # revocation with a bad hash must not be silently "recovered" away.
            if seq != expected_seq:
                raise TamperError(
                    f"sequence gap/out-of-order at line {idx + 1}: "
                    f"expected {expected_seq}, found {seq}"
                )
            if prev_h != prev:
                raise TamperError(f"prev-hash mismatch at seq {seq}")
            expect_h = compute_hash(seq, prev, kind, payload)
            if h != expect_h:
                raise TamperError(f"hash mismatch at seq {seq}")

            ev = StoredEvent(seq, prev_h, h, kind, payload)
            valid.append(ev)
            prev = h
            expected_seq += 1
            valid_raw_count += 1

        # If we discarded a torn tail, physically truncate it.
        if valid_raw_count < len(record_entries):
            # Keep exactly valid_raw_count non-empty records + terminal newline.
            self.sink.truncate_trailing(valid_raw_count)

        self._events = valid
        self._last_hash = prev
        self._maybe_trailing_empty = trailing_empty

    def verify(self) -> None:
        """Re-read from the sink and fully re-verify (used by proofs)."""
        fresh = DurableLog(self.sink)  # type: ignore[arg-type]
        if [e.to_line() for e in fresh.events()] != [
            e.to_line() for e in self._events
        ]:
            raise TamperError("on-disk log differs from in-memory fold")

    # -- append -------------------------------------------------------------

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def append(self, kind: str, payload: dict[str, Any] | None = None,
               sync: bool = True) -> StoredEvent:
        """Assign the next physical seq and durably append.

        ``sync=True`` forces fsync before return (critical control records).
        """
        payload = dict(payload or {})
        with self._lock:
            seq = len(self._events) + 1
            h = compute_hash(seq, self._last_hash, kind, payload)
            ev = StoredEvent(seq, self._last_hash, h, kind, payload)
            # Persist BEFORE publishing to the in-memory fold so the seq is
            # genuinely the on-disk sequence.
            self.sink.append_line(ev.to_line(), sync=sync)
            self._events.append(ev)
            self._last_hash = h
            return ev

    def fsync(self) -> None:
        with self._lock:
            self.sink.fsync()

    # -- readers ------------------------------------------------------------

    def events(self) -> list[StoredEvent]:
        with self._lock:
            return list(self._events)

    def last_seq(self) -> int:
        with self._lock:
            return len(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def close(self) -> None:
        if isinstance(self.sink, FileSink):
            self.sink.close()


def read_disk_events(path: str) -> list[StoredEvent]:
    """Open a file log read-only-ish and return its verified events."""
    log = DurableLog.open_file(path)
    evs = log.events()
    # Keep the handle lifecycle simple for an offline tool: fsync+close.
    log.close()
    return evs
