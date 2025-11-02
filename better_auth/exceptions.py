"""Exception classes for better-auth.

This module defines the standardized error hierarchy for Better Auth.
All error types follow the specification in ERRORS.md in the root repository.
"""

from typing import Any, Optional


class BetterAuthError(Exception):
    """Base exception class for all better-auth errors."""

    error_code: str = "BA000"

    def __init__(self, message: str, context: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary for serialization."""
        return {
            "error": {
                "code": self.error_code,
                "message": str(self),
                "context": self.context,
            }
        }


# ============================================================================
# Validation Errors
# ============================================================================


class InvalidMessageError(BetterAuthError):
    """Exception raised when a message is malformed or invalid."""

    error_code = "BA101"

    def __init__(self, field: Optional[str] = None, details: Optional[str] = None):
        message = (
            f"Message structure is invalid: {field}"
            if field
            else "Message structure is invalid or malformed"
        )
        if field and details:
            message += f" ({details})"
        super().__init__(message, {"field": field, "details": details})


class InvalidIdentityError(BetterAuthError):
    """Exception raised when identity verification fails."""

    error_code = "BA102"

    def __init__(self, provided: Optional[str] = None, details: Optional[str] = None):
        super().__init__("Identity verification failed", {"provided": provided, "details": details})


class InvalidDeviceError(BetterAuthError):
    """Exception raised when device hash validation fails."""

    error_code = "BA103"

    def __init__(self, provided: Optional[str] = None, calculated: Optional[str] = None):
        super().__init__(
            "Device hash does not match hash(publicKey || rotationHash)",
            {"provided": provided, "calculated": calculated},
        )


class InvalidHashError(BetterAuthError):
    """Exception raised when hash validation fails."""

    error_code = "BA104"

    def __init__(
        self,
        expected: Optional[str] = None,
        actual: Optional[str] = None,
        hash_type: Optional[str] = None,
    ):
        super().__init__(
            "Hash validation failed",
            {"expected": expected, "actual": actual, "hashType": hash_type},
        )


# ============================================================================
# Cryptographic Errors
# ============================================================================


class IncorrectNonceError(BetterAuthError):
    """Exception raised when response nonce doesn't match request nonce."""

    error_code = "BA203"

    def __init__(self, expected: Optional[str] = None, actual: Optional[str] = None):
        super().__init__(
            "Response nonce does not match request nonce",
            {
                "expected": expected[:16] + "..." if expected else None,
                "actual": actual[:16] + "..." if actual else None,
            },
        )


# ============================================================================
# Authentication/Authorization Errors
# ============================================================================


class MismatchedIdentitiesError(BetterAuthError):
    """Exception raised when link container identity doesn't match request identity."""

    error_code = "BA302"

    def __init__(
        self, link_container_identity: Optional[str] = None, request_identity: Optional[str] = None
    ):
        super().__init__(
            "Link container identity does not match request identity",
            {"linkContainerIdentity": link_container_identity, "requestIdentity": request_identity},
        )


# ============================================================================
# Token Errors
# ============================================================================


class ExpiredTokenError(BetterAuthError):
    """Exception raised when a token has expired."""

    error_code = "BA401"

    def __init__(
        self,
        expiry_time: Optional[str] = None,
        current_time: Optional[str] = None,
        token_type: Optional[str] = None,
    ):
        super().__init__(
            "Token has expired",
            {"expiryTime": expiry_time, "currentTime": current_time, "tokenType": token_type},
        )


class FutureTokenError(BetterAuthError):
    """Exception raised when token issued_at is in the future."""

    error_code = "BA403"

    def __init__(
        self,
        issued_at: Optional[str] = None,
        current_time: Optional[str] = None,
        time_difference: Optional[float] = None,
    ):
        super().__init__(
            "Token issued_at timestamp is in the future",
            {"issuedAt": issued_at, "currentTime": current_time, "timeDifference": time_difference},
        )


# ============================================================================
# Temporal Errors
# ============================================================================


class StaleRequestError(BetterAuthError):
    """Exception raised when request timestamp is too old."""

    error_code = "BA501"

    def __init__(
        self,
        request_timestamp: Optional[str] = None,
        current_time: Optional[str] = None,
        maximum_age: Optional[int] = None,
    ):
        super().__init__(
            "Request timestamp is too old",
            {
                "requestTimestamp": request_timestamp,
                "currentTime": current_time,
                "maximumAge": maximum_age,
            },
        )


class FutureRequestError(BetterAuthError):
    """Exception raised when request timestamp is in the future."""

    error_code = "BA502"

    def __init__(
        self,
        request_timestamp: Optional[str] = None,
        current_time: Optional[str] = None,
        time_difference: Optional[float] = None,
    ):
        super().__init__(
            "Request timestamp is in the future",
            {
                "requestTimestamp": request_timestamp,
                "currentTime": current_time,
                "timeDifference": time_difference,
            },
        )
