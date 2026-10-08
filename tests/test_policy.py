from secure_sandbox import ExecutionRequest, Policy, Sandbox

POLICY = Policy(frozenset({"python"}), network_hosts=frozenset({"api.example.com"}))


def test_allows_least_privilege_request():
    receipt = Sandbox(POLICY).admit(
        ExecutionRequest(("python", "job.py"), ("/workspace/output/a.json",))
    )
    assert receipt.decision == "allow"


def test_denies_unknown_command_and_path_escape():
    receipt = Sandbox(POLICY).admit(ExecutionRequest(("sh",), ("/workspace/output/../secret",)))
    assert receipt.decision == "deny"
    assert "command_not_allowed" in receipt.reasons


def test_denies_unlisted_or_insecure_network():
    receipt = Sandbox(POLICY).admit(
        ExecutionRequest(("python",), network_urls=("http://api.example.com", "https://evil.test"))
    )
    assert len([reason for reason in receipt.reasons if reason.startswith("network_denied")]) == 2


def test_enforces_resource_limits():
    receipt = Sandbox(POLICY).admit(ExecutionRequest(("python",), cpu_seconds=20, memory_mb=512))
    assert set(receipt.reasons) == {"cpu_limit_exceeded", "memory_limit_exceeded"}


def test_receipts_are_reproducible():
    request = ExecutionRequest(("python", "job.py"))
    assert Sandbox(POLICY).admit(request) == Sandbox(POLICY).admit(request)

