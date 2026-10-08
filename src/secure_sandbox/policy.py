from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from urllib.parse import urlparse


@dataclass(frozen=True)
class Policy:
    allowed_commands: frozenset[str]
    writable_roots: tuple[str, ...] = ("/workspace/output",)
    network_hosts: frozenset[str] = frozenset()
    max_cpu_seconds: int = 10
    max_memory_mb: int = 256
    max_output_bytes: int = 100_000


@dataclass(frozen=True)
class ExecutionRequest:
    command: tuple[str, ...]
    write_paths: tuple[str, ...] = ()
    network_urls: tuple[str, ...] = ()
    cpu_seconds: int = 1
    memory_mb: int = 64


@dataclass(frozen=True)
class Receipt:
    request_hash: str
    decision: str
    reasons: tuple[str, ...]
    policy_hash: str


class Sandbox:
    """Fail-closed admission layer; a container runtime can consume approved requests."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def admit(self, request: ExecutionRequest) -> Receipt:
        reasons: list[str] = []
        if not request.command or request.command[0] not in self.policy.allowed_commands:
            reasons.append("command_not_allowed")
        for path in request.write_paths:
            normalized = str(PurePosixPath(path))
            if ".." in PurePosixPath(path).parts or not any(
                normalized == root or normalized.startswith(root + "/")
                for root in self.policy.writable_roots
            ):
                reasons.append(f"write_denied:{path}")
        for url in request.network_urls:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if parsed.scheme != "https" or host not in self.policy.network_hosts:
                reasons.append(f"network_denied:{host or 'invalid'}")
            else:
                try:
                    if ipaddress.ip_address(host).is_private:
                        reasons.append(f"private_network_denied:{host}")
                except ValueError:
                    pass
        if request.cpu_seconds > self.policy.max_cpu_seconds:
            reasons.append("cpu_limit_exceeded")
        if request.memory_mb > self.policy.max_memory_mb:
            reasons.append("memory_limit_exceeded")
        request_hash = self._hash(asdict(request))
        policy_hash = self._hash(asdict(self.policy))
        return Receipt(request_hash, "deny" if reasons else "allow", tuple(reasons), policy_hash)

    @staticmethod
    def _hash(value: object) -> str:
        payload = json.dumps(value, sort_keys=True, default=sorted)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

