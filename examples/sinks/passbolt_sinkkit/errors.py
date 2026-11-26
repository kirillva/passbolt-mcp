"""Stable sink error types and exit codes.

Messages must never include a secret; guards raise field/rule names only.
"""

from __future__ import annotations


class SinkError(Exception):
    status = "error"
    exit_code = 9


class InputError(SinkError):
    status = "invalid_input"
    exit_code = 2


class JobError(InputError):
    status = "invalid_job"


class TargetError(SinkError):
    status = "no_target"
    exit_code = 3


class FormError(SinkError):
    status = "form_error"
    exit_code = 4


class SinkTimeout(SinkError):
    status = "timeout"
    exit_code = 5


class MfaRequired(SinkError):
    status = "mfa_required"
    exit_code = 6


class Denied(SinkError):
    status = "denied"
    exit_code = 7


class RemoteFailure(SinkError):
    status = "remote_error"
    exit_code = 8


class AuthRejected(RemoteFailure):
    """The site answered the submitted credential with a refusal."""

    status = "rejected"


class AuthUnconfirmed(SinkError):
    """The site neither accepted the credential visibly nor refused it."""

    status = "unconfirmed"
    exit_code = 8


class AccountMismatch(SinkError):
    status = "account_mismatch"
    exit_code = 8


EXIT_CODES = {
    "ok": 0,
    "logged_in": 0,
    "invalid_input": 2,
    "invalid_job": 2,
    "no_target": 3,
    "form_error": 4,
    "timeout": 5,
    "mfa_required": 6,
    "denied": 7,
    "remote_error": 8,
    "rejected": 8,
    "unconfirmed": 8,
    "account_mismatch": 8,
    "error": 9,
}


def exit_code_for(status: str) -> int:
    return EXIT_CODES.get(status, 9)
