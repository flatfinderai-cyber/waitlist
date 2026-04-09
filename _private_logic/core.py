"""
_private_logic/core.py

Proprietary algorithm stub.  The implementation of this function must
remain server-side and must never be serialised or transmitted to the
client-side browser environment.

Security requirements:
  - eval() is prohibited.
  - pickle is prohibited.
  - All inputs are validated via pydantic before reaching this function.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, field_validator


class InventionPayload(BaseModel):
    """Validated input payload for the invention logic."""

    action: str
    parameters: dict[str, Any] = {}

    @field_validator("action")
    @classmethod
    def action_must_be_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("action must not be empty")
        return value


class InventionResult(BaseModel):
    """Validated result returned by the invention logic."""

    status: str
    message: str
    data: dict[str, Any] = {}


def execute_invention_logic(payload: dict) -> dict:
    """
    Execute the proprietary invention logic.

    This is a stub implementation.  Replace the body of this function
    with the actual proprietary algorithm.  The function must:
      - Accept a plain dict (validated internally via InventionPayload).
      - Return a plain dict (derived from InventionResult).
      - Never call eval() or use pickle.
      - Never expose intermediate state to the caller beyond the
        returned dict.

    Args:
        payload: A dictionary containing at minimum an 'action' key.

    Returns:
        A dictionary with 'status', 'message', and optional 'data' keys.
    """
    validated_input = InventionPayload(**payload)

    # ------------------------------------------------------------------ #
    # TODO: Replace the stub below with the real proprietary algorithm.   #
    # ------------------------------------------------------------------ #
    result = InventionResult(
        status="ok",
        message=f"Stub executed successfully for action '{validated_input.action}'.",
        data={"received_parameters": validated_input.parameters},
    )

    return result.model_dump()
