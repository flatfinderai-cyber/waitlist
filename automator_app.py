"""
automator_app.py — FlatFinder Automator
========================================
A unified Python 3.12+ web application built with Reflex.

Architecture decisions
----------------------
* All UI and state management live in a single Python file (no JS).
* eval() and pickle are prohibited throughout this codebase.
* Subprocess is used to run terminal commands (bandit, gcloud, vercel…).
* Proprietary logic is isolated in _private_logic/core.py and is
  never serialised to the client-side browser environment.
* Pydantic validates all untrusted inputs before they reach state
  methods or private logic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess  # noqa: S404  — intentional; see security note below
import sys
from pathlib import Path
from typing import Any

import reflex as rx
import yaml
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Security note: subprocess is used deliberately to execute deployment CLI
# tools (gcloud, vercel, firebase).  All commands are constructed from a
# fixed allow-list in config.yaml — no user-supplied strings are ever passed
# directly to the shell.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Pydantic models for input validation
# ---------------------------------------------------------------------------


class WalletAddress(BaseModel):
    """Validated Ethereum wallet address."""

    address: str

    @field_validator("address")
    @classmethod
    def must_be_valid_eth_address(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^0x[0-9a-fA-F]{40}$", v):
            raise ValueError("Invalid Ethereum address format")
        return v.lower()


class LemonSqueezyWebhookPayload(BaseModel):
    """Minimal validated Lemon Squeezy webhook envelope."""

    event_name: str
    meta: dict[str, Any] = {}
    data: dict[str, Any] = {}

    @field_validator("event_name")
    @classmethod
    def event_must_be_non_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("event_name must not be empty")
        return v


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path("config.yaml")


def _load_config() -> dict:
    """Load and return the application configuration from config.yaml."""
    if not _CONFIG_PATH.exists():
        return {}
    with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _get_deployment_targets(config: dict) -> list[dict]:
    return config.get("deployment_targets", [])


# ---------------------------------------------------------------------------
# SIWE / WalletConnect authentication stub
# ---------------------------------------------------------------------------


def verify_siwe_signature(address: str, message: str, signature: str) -> bool:
    """
    Verify a Sign-In with Ethereum (SIWE) signature.

    This is a stub implementation.  In production, replace this function
    with a proper SIWE library call (e.g. siwe-py).  The stub always
    returns False so that unauthenticated access is blocked by default.

    Args:
        address:   The claimed Ethereum address (already validated).
        message:   The EIP-4361 message that was signed.
        signature: The hex-encoded signature produced by the wallet.

    Returns:
        True only when the signature is cryptographically valid.
    """
    # TODO: integrate siwe-py or web3.py for production signature verification.
    _ = address, message, signature  # suppress unused-variable warnings
    return False


# ---------------------------------------------------------------------------
# Lemon Squeezy webhook verification stub
# ---------------------------------------------------------------------------

_LEMON_SQUEEZY_SECRET = os.environ.get("LEMON_SQUEEZY_WEBHOOK_SECRET", "")


def verify_lemon_squeezy_webhook(
    raw_body: bytes,
    signature_header: str,
) -> bool:
    """
    Verify the HMAC-SHA256 signature of an incoming Lemon Squeezy webhook.

    Args:
        raw_body:          The raw request body bytes.
        signature_header:  The value of the X-Signature header.

    Returns:
        True when the signature matches the configured secret.
    """
    if not _LEMON_SQUEEZY_SECRET:
        return False
    expected = hmac.new(
        _LEMON_SQUEEZY_SECRET.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ---------------------------------------------------------------------------
# Reflex state
# ---------------------------------------------------------------------------


class FactoryState(rx.State):
    """Central state for the FlatFinder Automator control panel."""

    # ----- Authentication & subscription -----
    is_authenticated: bool = False
    has_active_subscription: bool = False
    wallet_address: str = ""

    # ----- UI fields -----
    wallet_input: str = ""
    message_input: str = ""
    signature_input: str = ""

    # ----- Output panels -----
    spec_output: str = ""
    audit_output: str = ""
    engine_output: str = ""
    deploy_output: str = ""
    auth_output: str = ""

    # ----- Deployment selection -----
    selected_target: str = ""
    available_targets: list[str] = []

    # ----- Internal: loaded config -----
    _config: dict = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_load(self) -> None:
        """Initialise state when the page loads."""
        self._config = _load_config()
        targets = _get_deployment_targets(self._config)
        self.available_targets = [t["name"] for t in targets]
        if self.available_targets:
            self.selected_target = self.available_targets[0]

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def connect_wallet(self) -> None:
        """
        Stub: connect a wallet via WalletConnect / SIWE.

        In production this would trigger the WalletConnect modal in the
        browser and return a signed SIWE message.  Here we validate the
        form inputs and call the SIWE verification stub.
        """
        try:
            validated = WalletAddress(address=self.wallet_input)
        except Exception as exc:
            self.auth_output = f"[ERROR] Invalid wallet address: {exc}"
            return

        if not self.message_input or not self.signature_input:
            self.auth_output = "[INFO] Please provide a SIWE message and signature."
            return

        ok = verify_siwe_signature(
            validated.address,
            self.message_input,
            self.signature_input,
        )

        if ok:
            self.is_authenticated = True
            self.wallet_address = validated.address
            self.auth_output = (
                f"[OK] Authenticated as {validated.address}"
            )
        else:
            self.is_authenticated = False
            self.auth_output = (
                "[STUB] SIWE verification not yet implemented. "
                "Replace verify_siwe_signature() with a real implementation."
            )

    def disconnect_wallet(self) -> None:
        """Disconnect the current wallet session."""
        self.is_authenticated = False
        self.has_active_subscription = False
        self.wallet_address = ""
        self.wallet_input = ""
        self.message_input = ""
        self.signature_input = ""
        self.auth_output = "[INFO] Wallet disconnected."

    def activate_subscription(self) -> None:
        """Stub: mark the current session as having an active subscription."""
        if not self.is_authenticated:
            self.auth_output = "[ERROR] You must authenticate before activating a subscription."
            return
        # TODO: verify against Lemon Squeezy subscription API.
        self.has_active_subscription = True
        self.auth_output = (
            "[STUB] Subscription activated (stub). "
            "Replace with real Lemon Squeezy API verification."
        )

    # ------------------------------------------------------------------
    # Guard helper
    # ------------------------------------------------------------------

    def _check_access(self) -> bool:
        """Return True only when both auth and subscription are verified."""
        return self.is_authenticated and self.has_active_subscription

    # ------------------------------------------------------------------
    # Control panel actions
    # ------------------------------------------------------------------

    def read_specification(self) -> None:
        """Parse config.yaml and display its contents in the UI."""
        if not self._check_access():
            self.spec_output = (
                "[DENIED] You must be authenticated and have an active "
                "subscription to use this control."
            )
            return
        try:
            config = _load_config()
            if config:
                self.spec_output = json.dumps(config, indent=2, default=str)
            else:
                self.spec_output = "[INFO] config.yaml is empty or not found."
        except Exception as exc:
            self.spec_output = f"[ERROR] Failed to read config.yaml: {exc}"

    def run_security_audit(self) -> None:
        """Run bandit against _private_logic/ and stream output to the UI."""
        if not self._check_access():
            self.audit_output = (
                "[DENIED] You must be authenticated and have an active "
                "subscription to use this control."
            )
            return
        config = _load_config()
        scan_path = config.get("security", {}).get(
            "bandit_scan_path", "./_private_logic"
        )
        # Resolve to an absolute path so subprocess.run() is not affected
        # by a changed working directory.
        abs_scan_path = str(Path(scan_path).resolve())
        try:
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "bandit", "-r", abs_scan_path],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.audit_output = combined if combined else "[OK] No output."
        except FileNotFoundError:
            self.audit_output = (
                "[ERROR] bandit is not installed. "
                "Run: pip install bandit"
            )
        except subprocess.TimeoutExpired:
            self.audit_output = "[ERROR] bandit timed out after 120 seconds."
        except Exception as exc:
            self.audit_output = f"[ERROR] Unexpected error: {exc}"

    def test_engine(self) -> None:
        """Pass a test payload to _private_logic/core.py and show the result."""
        if not self._check_access():
            self.engine_output = (
                "[DENIED] You must be authenticated and have an active "
                "subscription to use this control."
            )
            return
        try:
            from _private_logic.core import execute_invention_logic

            test_payload = {"action": "test_run", "parameters": {"env": "dev"}}
            result = execute_invention_logic(test_payload)
            self.engine_output = json.dumps(result, indent=2, default=str)
        except Exception as exc:
            self.engine_output = f"[ERROR] Engine test failed: {exc}"

    def deploy(self) -> None:
        """Execute the deployment command for the selected target."""
        if not self._check_access():
            self.deploy_output = (
                "[DENIED] You must be authenticated and have an active "
                "subscription to use this control."
            )
            return
        config = _load_config()
        targets = {t["name"]: t for t in _get_deployment_targets(config)}
        if self.selected_target not in targets:
            self.deploy_output = (
                f"[ERROR] Unknown deployment target: {self.selected_target!r}"
            )
            return
        raw_command: str = targets[self.selected_target]["command"]
        # Use shlex.split() to correctly handle quoted arguments and paths
        # with spaces.  Commands are sourced from the config allow-list, not
        # from user input, so this is safe.
        command_parts = shlex.split(raw_command)
        try:
            result = subprocess.run(  # noqa: S603
                command_parts,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.deploy_output = combined if combined else "[OK] Deployment complete."
        except FileNotFoundError:
            self.deploy_output = (
                f"[ERROR] Command not found: {command_parts[0]!r}. "
                "Ensure the deployment CLI is installed."
            )
        except subprocess.TimeoutExpired:
            self.deploy_output = "[ERROR] Deployment timed out after 300 seconds."
        except Exception as exc:
            self.deploy_output = f"[ERROR] Unexpected error: {exc}"

    # ------------------------------------------------------------------
    # Form field setters
    # ------------------------------------------------------------------

    def set_wallet_input(self, value: str) -> None:
        self.wallet_input = value

    def set_message_input(self, value: str) -> None:
        self.message_input = value

    def set_signature_input(self, value: str) -> None:
        self.signature_input = value

    def set_selected_target(self, value: str) -> None:
        self.selected_target = value


# ---------------------------------------------------------------------------
# UI helpers / components
# ---------------------------------------------------------------------------


def _section_heading(text: str) -> rx.Component:
    return rx.heading(
        text,
        size="4",
        color="#e8830c",
        margin_bottom="0.5em",
    )


def _output_box(content: str, min_height: str = "80px") -> rx.Component:
    return rx.box(
        rx.text(content, white_space="pre-wrap", font_size="0.85em"),
        border="1px solid #444",
        border_radius="6px",
        padding="0.75em",
        background="#1a1a2e",
        color="#c8d6e5",
        min_height=min_height,
        width="100%",
        overflow_y="auto",
    )


def _action_button(label: str, on_click: Any, color: str = "#e8830c") -> rx.Component:
    return rx.button(
        label,
        on_click=on_click,
        background=color,
        color="white",
        border_radius="6px",
        padding="0.5em 1.2em",
        cursor="pointer",
        _hover={"opacity": "0.85"},
    )


# ---------------------------------------------------------------------------
# Mascot component — Benny the orange tabby cat
# ---------------------------------------------------------------------------


def benny_mascot() -> rx.Component:
    """
    Visual placeholder for Benny — an orange tabby cat in a mechanic's apron.

    Replace the SVG artwork with a real asset when it becomes available.
    """
    return rx.box(
        # Outer circle badge
        rx.box(
            # Cat face — orange tabby colouring
            rx.box(
                # Eyes
                rx.hstack(
                    rx.box(
                        width="10px",
                        height="10px",
                        background="#2c3e50",
                        border_radius="50%",
                    ),
                    rx.box(
                        width="10px",
                        height="10px",
                        background="#2c3e50",
                        border_radius="50%",
                    ),
                    spacing="2",
                    justify="center",
                    margin_bottom="4px",
                ),
                # Nose
                rx.box(
                    width="6px",
                    height="4px",
                    background="#e74c3c",
                    border_radius="50%",
                    margin="0 auto 4px",
                ),
                # Whiskers
                rx.hstack(
                    rx.box(width="25px", height="1px", background="#555"),
                    rx.box(width="25px", height="1px", background="#555"),
                    spacing="3",
                    justify="center",
                ),
                padding="12px",
                background="#f39c12",
                border_radius="50%",
                width="80px",
                height="80px",
                display="flex",
                flex_direction="column",
                align_items="center",
                justify_content="center",
                border="3px solid #d35400",
            ),
            # Mechanic's apron label
            rx.box(
                rx.text("🔧", font_size="1.2em"),
                rx.text(
                    "BENNY",
                    font_size="0.55em",
                    font_weight="bold",
                    color="white",
                    letter_spacing="0.1em",
                ),
                background="#2c3e50",
                border_radius="4px",
                padding="4px 8px",
                margin_top="6px",
                display="flex",
                flex_direction="column",
                align_items="center",
            ),
            display="flex",
            flex_direction="column",
            align_items="center",
        ),
        rx.text(
            "Your engineering companion",
            font_size="0.75em",
            color="#95a5a6",
            margin_top="6px",
        ),
        display="flex",
        flex_direction="column",
        align_items="center",
        padding="1em",
    )


# ---------------------------------------------------------------------------
# Authentication panel
# ---------------------------------------------------------------------------


def auth_panel() -> rx.Component:
    return rx.box(
        _section_heading("🔐 Wallet Authentication (SIWE / WalletConnect)"),
        rx.vstack(
            rx.input(
                placeholder="Ethereum address (0x…)",
                value=FactoryState.wallet_input,
                on_change=FactoryState.set_wallet_input,
                width="100%",
            ),
            rx.textarea(
                placeholder="EIP-4361 SIWE message…",
                value=FactoryState.message_input,
                on_change=FactoryState.set_message_input,
                width="100%",
                rows="3",
            ),
            rx.input(
                placeholder="Signature (0x…)",
                value=FactoryState.signature_input,
                on_change=FactoryState.set_signature_input,
                width="100%",
            ),
            rx.hstack(
                _action_button("Connect Wallet", FactoryState.connect_wallet),
                _action_button(
                    "Activate Subscription",
                    FactoryState.activate_subscription,
                    color="#27ae60",
                ),
                _action_button(
                    "Disconnect",
                    FactoryState.disconnect_wallet,
                    color="#c0392b",
                ),
                spacing="3",
                flex_wrap="wrap",
            ),
            rx.hstack(
                rx.text("Auth: ", font_weight="bold", color="#bdc3c7"),
                rx.cond(
                    FactoryState.is_authenticated,
                    rx.badge("✔ Authenticated", color_scheme="green"),
                    rx.badge("✘ Not authenticated", color_scheme="red"),
                ),
                rx.text("  |  Subscription: ", font_weight="bold", color="#bdc3c7"),
                rx.cond(
                    FactoryState.has_active_subscription,
                    rx.badge("✔ Active", color_scheme="green"),
                    rx.badge("✘ Inactive", color_scheme="orange"),
                ),
                spacing="1",
                flex_wrap="wrap",
            ),
            _output_box(FactoryState.auth_output),
            spacing="3",
            width="100%",
            align_items="flex-start",
        ),
        padding="1.25em",
        border="1px solid #333",
        border_radius="8px",
        background="#0f0f23",
        width="100%",
    )


# ---------------------------------------------------------------------------
# Control panel
# ---------------------------------------------------------------------------


def control_panel() -> rx.Component:
    return rx.box(
        _section_heading("⚙️ Control Panel"),
        rx.vstack(
            # -- Read Specification --
            rx.box(
                rx.text(
                    "Read Specification",
                    font_weight="bold",
                    color="#ecf0f1",
                    margin_bottom="0.4em",
                ),
                rx.text(
                    "Parses config.yaml and displays the current configuration.",
                    font_size="0.8em",
                    color="#95a5a6",
                    margin_bottom="0.6em",
                ),
                _action_button("📄 Read Specification", FactoryState.read_specification),
                _output_box(FactoryState.spec_output),
                width="100%",
            ),
            rx.divider(color="#333"),
            # -- Security Audit --
            rx.box(
                rx.text(
                    "Security Audit",
                    font_weight="bold",
                    color="#ecf0f1",
                    margin_bottom="0.4em",
                ),
                rx.text(
                    "Runs bandit -r ./_private_logic and outputs the result.",
                    font_size="0.8em",
                    color="#95a5a6",
                    margin_bottom="0.6em",
                ),
                _action_button(
                    "🔍 Run Security Audit",
                    FactoryState.run_security_audit,
                    color="#8e44ad",
                ),
                _output_box(FactoryState.audit_output, min_height="120px"),
                width="100%",
            ),
            rx.divider(color="#333"),
            # -- Test Engine --
            rx.box(
                rx.text(
                    "Test Engine",
                    font_weight="bold",
                    color="#ecf0f1",
                    margin_bottom="0.4em",
                ),
                rx.text(
                    "Sends a test payload to _private_logic/core.py and shows the result.",
                    font_size="0.8em",
                    color="#95a5a6",
                    margin_bottom="0.6em",
                ),
                _action_button(
                    "🧪 Test Engine",
                    FactoryState.test_engine,
                    color="#2980b9",
                ),
                _output_box(FactoryState.engine_output),
                width="100%",
            ),
            rx.divider(color="#333"),
            # -- Deploy --
            rx.box(
                rx.text(
                    "Deploy",
                    font_weight="bold",
                    color="#ecf0f1",
                    margin_bottom="0.4em",
                ),
                rx.text(
                    "Select a deployment target and execute the corresponding CLI command.",
                    font_size="0.8em",
                    color="#95a5a6",
                    margin_bottom="0.6em",
                ),
                rx.hstack(
                    rx.select(
                        FactoryState.available_targets,
                        value=FactoryState.selected_target,
                        on_change=FactoryState.set_selected_target,
                        width="160px",
                    ),
                    _action_button(
                        "🚀 Deploy",
                        FactoryState.deploy,
                        color="#16a085",
                    ),
                    spacing="3",
                    align_items="center",
                ),
                _output_box(FactoryState.deploy_output, min_height="100px"),
                width="100%",
            ),
            spacing="4",
            width="100%",
            align_items="flex-start",
        ),
        padding="1.25em",
        border="1px solid #333",
        border_radius="8px",
        background="#0f0f23",
        width="100%",
    )


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------


def index() -> rx.Component:
    return rx.box(
        # Header
        rx.hstack(
            benny_mascot(),
            rx.vstack(
                rx.heading(
                    "FlatFinder Automator",
                    size="6",
                    color="#e8830c",
                ),
                rx.text(
                    "Unified Python deployment & prototype execution environment",
                    color="#7f8c8d",
                    font_size="0.9em",
                ),
                align_items="flex-start",
                spacing="1",
            ),
            spacing="5",
            align_items="center",
            padding="1em 0",
        ),
        rx.divider(color="#333", margin_y="0.75em"),
        # Main content
        rx.vstack(
            auth_panel(),
            control_panel(),
            spacing="5",
            width="100%",
        ),
        # Footer
        rx.text(
            "FlatFinder Automator · Python 3.12+ · Reflex · All logic server-side",
            font_size="0.7em",
            color="#444",
            text_align="center",
            margin_top="2em",
            padding_bottom="1em",
        ),
        max_width="860px",
        margin="0 auto",
        padding="1.5em",
        min_height="100vh",
        background="#080818",
        color="#ecf0f1",
    )


# ---------------------------------------------------------------------------
# App definition
# ---------------------------------------------------------------------------

app = rx.App(
    style={
        "font_family": "'Segoe UI', Arial, sans-serif",
        "background": "#080818",
    }
)
app.add_page(index, on_load=FactoryState.on_load)
