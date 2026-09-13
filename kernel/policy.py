"""ApprovalPolicy: AutoApprove | AutoDeny | Interactive.

Injected into the broker, never hardcoded. Eval mode uses the Auto* policies so the
suite never blocks on input.
"""
from abc import ABC, abstractmethod
from typing import Callable


class ApprovalPolicy(ABC):
    name = "abstract"

    @abstractmethod
    def approve(self, tool: str, args: dict, reason: str) -> bool: ...


class AutoApprove(ApprovalPolicy):
    name = "auto_approve"

    def approve(self, tool: str, args: dict, reason: str) -> bool:
        return True


class AutoDeny(ApprovalPolicy):
    name = "auto_deny"

    def approve(self, tool: str, args: dict, reason: str) -> bool:
        return False


class Interactive(ApprovalPolicy):
    name = "interactive"

    def __init__(self, prompt_fn: Callable[[str], str] = input,
                 print_fn: Callable[[str], None] = print) -> None:
        self.prompt_fn = prompt_fn
        self.print_fn = print_fn

    def approve(self, tool: str, args: dict, reason: str) -> bool:
        from kernel.taint import unwrap
        self.print_fn(f"\nAPPROVAL REQUIRED: {tool}\n  reason: {reason}")
        for key, value in unwrap(args).items():
            self.print_fn(f"  {key}: {str(value)[:500]}")
        return self.prompt_fn("Approve? [y/N] ").strip().lower() in ("y", "yes")
