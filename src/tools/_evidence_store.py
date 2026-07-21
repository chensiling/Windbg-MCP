"""Bounded in-memory storage for raw debugger evidence."""

from collections import OrderedDict
from dataclasses import dataclass
import secrets
from threading import Lock
import time


_MAX_RECORDS = 64
_MAX_RECORD_CHARS = 1_000_000
_TTL_SECONDS = 15 * 60


@dataclass(frozen=True)
class EvidenceRecord:
    command_id: str
    output: str
    original_size: int
    stored_size: int
    truncated: bool
    created_at: float


class EvidenceStore:
    def __init__(self) -> None:
        self._records: OrderedDict[str, EvidenceRecord] = OrderedDict()
        self._lock = Lock()

    def put(self, command_id: str, output: str) -> EvidenceRecord:
        evidence_id = command_id or f"ev-{secrets.token_hex(16)}"
        now = time.monotonic()
        stored_output = output[:_MAX_RECORD_CHARS]
        record = EvidenceRecord(
            command_id=evidence_id,
            output=stored_output,
            original_size=len(output),
            stored_size=len(stored_output),
            truncated=len(stored_output) != len(output),
            created_at=now,
        )
        with self._lock:
            self._expire_locked(now)
            self._records[evidence_id] = record
            self._records.move_to_end(evidence_id)
            while len(self._records) > _MAX_RECORDS:
                self._records.popitem(last=False)
        return record

    def get(self, command_id: str) -> EvidenceRecord | None:
        now = time.monotonic()
        with self._lock:
            self._expire_locked(now)
            record = self._records.get(command_id)
            if record is not None:
                self._records.move_to_end(command_id)
            return record

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def _expire_locked(self, now: float) -> None:
        expired = [
            command_id
            for command_id, record in self._records.items()
            if now - record.created_at > _TTL_SECONDS
        ]
        for command_id in expired:
            self._records.pop(command_id, None)


_STORE = EvidenceStore()


def store_evidence(command_id: str, output: str) -> EvidenceRecord:
    return _STORE.put(command_id, output)


def get_evidence(command_id: str) -> EvidenceRecord | None:
    return _STORE.get(command_id)


def clear_evidence() -> None:
    _STORE.clear()
