# Secure Agent Sandbox

[![CI](https://github.com/ZhengjunSun/secure-agent-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/ZhengjunSun/secure-agent-sandbox/actions/workflows/ci.yml)

A fail-closed admission and audit layer for code-executing AI agents. It validates command capabilities, writable paths, outbound HTTPS hosts, and resource requests before a container or microVM runtime receives a job.

```text
agent tool call -> normalized request -> policy checks -> allow/deny receipt -> runtime adapter
```

## Demonstrated controls

- Command allow-list instead of unrestricted shell access.
- Workspace-root enforcement and traversal rejection.
- HTTPS network allow-list with explicit private-address blocking.
- CPU and memory budgets.
- Content-addressed request and policy receipts for later audit.
- A transport-neutral boundary suitable for Docker, gVisor, Firecracker, E2B, or Daytona adapters.

The repository deliberately does not pretend that a Python function is an isolation boundary. It implements the policy plane and makes the runtime boundary explicit.

```bash
python -m pip install -e ".[dev]"
pytest -q
```

All examples are synthetic. MIT licensed.

