"""Source-owned durable handoff and exact retry reconciliation."""

import json

from .errors import ServiceError
from .contracts import canonical
from .runtime_port import RuntimeCallError, RuntimeClient, expected_run_id


def public_handoff(record: dict | None) -> dict | None:
    if record is None: return None
    return {key: record[key] for key in ("event_id", "revision_id", "state", "attempts", "last_error", "uncertain", "run_id")}


class OutboxDelivery:
    def __init__(self, storage, runtime: RuntimeClient):
        self.storage, self.runtime = storage, runtime

    def pending(self, *, after="", limit=100) -> list[dict]:
        return self.storage.transact(lambda tx: [public_handoff(item) for item in tx.pending_handoffs(after, limit)])

    def reconcile(self, event_id: str, *, retry_failed=False) -> dict:
        def begin(tx):
            row = tx.get_handoff(event_id)
            if row is None: raise ServiceError("not_found")
            if row["state"] == "started" or (row["state"] == "failed" and not retry_failed):
                return row, None, False
            # A process exit between send and receipt is uncertain on restart.
            updated = {**row, "state": "pending", "uncertain": True, "version": row["version"] + 1, "attempts": row["attempts"] + 1}
            tx.update_handoff(updated, row["version"])
            tx.record_delivery_attempt(event_id, updated["attempts"], {"state": "attempted", "command_id": row["command"]["request_id"]})
            return updated, updated["attempts"], row.get("uncertain", False)
        row, attempt, previously_uncertain = self.storage.transact(begin)
        if attempt is None: return public_handoff(row)
        receipt, error, state = None, None, "pending"
        try:
            # The adapter receives a value copy; it cannot mutate the retained
            # command against which its acknowledgement will be checked.
            command = json.loads(canonical(row["command"]))
            recover = getattr(self.runtime, "resume_command", None)
            if previously_uncertain and callable(recover):
                receipt = json.loads(canonical(recover(command)))
            else:
                receipt = json.loads(canonical(self.runtime.command(command)))
            self._check_receipt(row, receipt)
            state = "started"
        except RuntimeCallError as failure:
            known = {"unsupported_contract", "incompatible_version", "forbidden", "unauthenticated", "not_found", "invalid_dag", "type_mismatch", "idempotency_conflict", "storage_unavailable", "unknown_outcome", "not_ready"}
            error = failure.code if failure.code in known else "runtime_rejected"
            state = "pending" if failure.retryable or failure.uncertain else "failed"
        except (TimeoutError, OSError):
            error = "unknown_outcome"
        except (ServiceError, ValueError, TypeError, KeyError):
            # A malformed acknowledgement is an uncertain create, not proof of failure.
            error = "runtime_contract"
        def finish(tx):
            current = tx.get_handoff(event_id)
            tx.record_delivery_attempt(event_id, attempt, {"state": state, "error": error, "receipt": receipt if state == "started" else None})
            # A late failure cannot erase another delivery's valid acknowledgement.
            if current["state"] == "started": return current
            if state != "started" and current["attempts"] > attempt: return current
            final_state = "pending" if state == "failed" and previously_uncertain else state
            updated = {**current, "state": final_state, "version": current["version"] + 1,
                       "last_error": error, "receipt": receipt if state == "started" else None,
                       "uncertain": final_state == "pending",
                       "run_id": receipt["result"]["run_id"] if state == "started" else None}
            tx.update_handoff(updated, current["version"])
            return updated
        return public_handoff(self.storage.transact(finish))

    @staticmethod
    def _check_receipt(row: dict, receipt: dict):
        command, event = row["command"], row["command"]["payload"]
        if (not isinstance(receipt, dict) or set(receipt) != {"schema", "request_id", "operation", "duplicate", "resource", "version", "result"}
                or receipt["schema"] != "runtime.result.v1" or any(receipt[key] != command[key] for key in ("request_id", "operation", "resource"))
                or type(receipt["duplicate"]) is not bool or type(receipt["version"]) is not int or receipt["version"] < 1):
            raise ServiceError("runtime_contract")
        data = receipt["result"]
        required = {"run_id", "pin", "state", "source_event_id"}
        if (not isinstance(data, dict) or not required <= set(data) <= required | {"run_state", "run_version"}
                or data["run_id"] != expected_run_id(event) or data["pin"] != event["pin"]
                or data["source_event_id"] != event["event_id"] or data["state"] not in {"pending", "running", "succeeded", "failed", "cancelled", "blocked"}):
            raise ServiceError("runtime_contract")
        if "run_state" in data and data["run_state"] != data["state"]: raise ServiceError("runtime_contract")
        if "run_version" in data and (type(data["run_version"]) is not int or data["run_version"] < 1): raise ServiceError("runtime_contract")
