"""Transport adapters may translate to v1, but cannot mutate aggregates."""

from .application import Service
from .contracts import Command


class CommandIngress:
    def __init__(self, service: Service):
        self._service = service

    def submit(self, command_bytes: bytes, *, authority_evidence: bytes | None = None) -> dict:
        # Parsing and all authorization/lifecycle decisions are owned by Service.
        # Native secS evidence is verified by the application-owned receiver port.
        return self._service.execute(command_bytes, authority_evidence)

    def query(self, query_bytes: bytes, *, authority_evidence: bytes | None = None) -> dict:
        return self._service.query(query_bytes, authority_evidence)

    def readiness(self) -> dict:
        return self._service.readiness()


def validate_ingress_command(command_bytes: bytes) -> Command:
    """Optional normalization check; it is never an authorization decision."""
    return Command.parse(command_bytes)
