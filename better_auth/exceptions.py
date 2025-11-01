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


class SignatureVerificationError(BetterAuthError):
    """Exception raised when signature verification fails."""

    error_code = "BA201"

    def __init__(self, public_key: Optional[str] = None, signed_data: Optional[str] = None):
        super().__init__(
            "Signature verification failed", {"publicKey": public_key, "signedData": signed_data}
        )


class NonceError(BetterAuthError):
    """Base exception for nonce-related errors."""

    error_code = "BA202"


class IncorrectNonceError(NonceError):
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


class ExpiredNonceError(NonceError):
    """Exception raised when authentication challenge has expired."""

    error_code = "BA204"

    def __init__(
        self,
        nonce_timestamp: Optional[str] = None,
        current_time: Optional[str] = None,
        expiration_window: Optional[str] = None,
    ):
        super().__init__(
            "Authentication challenge has expired",
            {
                "nonceTimestamp": nonce_timestamp,
                "currentTime": current_time,
                "expirationWindow": expiration_window,
            },
        )


class NonceReplayError(NonceError):
    """Exception raised when nonce replay attack is detected."""

    error_code = "BA205"

    def __init__(self, nonce: Optional[str] = None, previous_usage_timestamp: Optional[str] = None):
        super().__init__(
            "Nonce has already been used (replay attack detected)",
            {
                "nonce": nonce[:16] + "..." if nonce else None,
                "previousUsageTimestamp": previous_usage_timestamp,
            },
        )


# ============================================================================
# Authentication/Authorization Errors
# ============================================================================


class AuthenticationError(BetterAuthError):
    """Base exception for authentication failures."""

    error_code = "BA301"


class MismatchedIdentitiesError(AuthenticationError):
    """Exception raised when link container identity doesn't match request identity."""

    error_code = "BA302"

    def __init__(
        self, link_container_identity: Optional[str] = None, request_identity: Optional[str] = None
    ):
        super().__init__(
            "Link container identity does not match request identity",
            {"linkContainerIdentity": link_container_identity, "requestIdentity": request_identity},
        )


class PermissionDeniedError(BetterAuthError):
    """Exception raised for insufficient permissions."""

    error_code = "BA303"

    def __init__(
        self,
        required_permissions: Optional[list[str]] = None,
        actual_permissions: Optional[list[str]] = None,
        operation: Optional[str] = None,
    ):
        super().__init__(
            "Insufficient permissions for requested operation",
            {
                "requiredPermissions": required_permissions,
                "actualPermissions": actual_permissions,
                "operation": operation,
            },
        )


# ============================================================================
# Token Errors
# ============================================================================


class TokenError(BetterAuthError):
    """Base exception for token-related errors."""

    error_code = "BA400"


class ExpiredTokenError(TokenError):
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


class InvalidTokenError(TokenError):
    """Exception raised when token structure or format is invalid."""

    error_code = "BA402"

    def __init__(self, details: Optional[str] = None):
        super().__init__("Token structure or format is invalid", {"details": details})


class FutureTokenError(TokenError):
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


class TemporalError(BetterAuthError):
    """Base exception for time-related errors."""

    error_code = "BA500"


class StaleRequestError(TemporalError):
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


class FutureRequestError(TemporalError):
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


class ClockSkewError(TemporalError):
    """Exception raised when client/server clock difference exceeds tolerance."""

    error_code = "BA503"

    def __init__(
        self,
        client_time: Optional[str] = None,
        server_time: Optional[str] = None,
        time_difference: Optional[float] = None,
        max_tolerance: Optional[float] = None,
    ):
        super().__init__(
            "Client and server clock difference exceeds tolerance",
            {
                "clientTime": client_time,
                "serverTime": server_time,
                "timeDifference": time_difference,
                "maxTolerance": max_tolerance,
            },
        )


# ============================================================================
# Storage Errors
# ============================================================================


class StorageError(BetterAuthError):
    """Base exception for storage-related errors."""

    error_code = "BA600"


class NotFoundError(StorageError):
    """Exception raised when a resource is not found."""

    error_code = "BA601"

    def __init__(
        self, resource_type: Optional[str] = None, resource_identifier: Optional[str] = None
    ):
        message = f"Resource not found: {resource_type}" if resource_type else "Resource not found"
        super().__init__(
            message, {"resourceType": resource_type, "resourceIdentifier": resource_identifier}
        )


class AlreadyExistsError(StorageError):
    """Exception raised when a resource already exists."""

    error_code = "BA602"

    def __init__(
        self, resource_type: Optional[str] = None, resource_identifier: Optional[str] = None
    ):
        message = (
            f"Resource already exists: {resource_type}"
            if resource_type
            else "Resource already exists"
        )
        super().__init__(
            message, {"resourceType": resource_type, "resourceIdentifier": resource_identifier}
        )


class StorageUnavailableError(StorageError):
    """Exception raised when storage backend is unavailable."""

    error_code = "BA603"

    def __init__(
        self,
        backend_type: Optional[str] = None,
        connection_details: Optional[str] = None,
        backend_error: Optional[str] = None,
    ):
        super().__init__(
            "Storage backend is unavailable",
            {
                "backendType": backend_type,
                "connectionDetails": connection_details,
                "backendError": backend_error,
            },
        )


class StorageCorruptionError(StorageError):
    """Exception raised when stored data is corrupted."""

    error_code = "BA604"

    def __init__(
        self,
        resource_type: Optional[str] = None,
        resource_identifier: Optional[str] = None,
        corruption_details: Optional[str] = None,
    ):
        super().__init__(
            "Stored data is corrupted or invalid",
            {
                "resourceType": resource_type,
                "resourceIdentifier": resource_identifier,
                "corruptionDetails": corruption_details,
            },
        )


# ============================================================================
# Encoding Errors
# ============================================================================


class EncodingError(BetterAuthError):
    """Base exception for encoding/serialization errors."""

    error_code = "BA700"


class SerializationError(EncodingError):
    """Exception raised when message serialization fails."""

    error_code = "BA701"

    def __init__(
        self,
        message_type: Optional[str] = None,
        format: Optional[str] = None,
        details: Optional[str] = None,
    ):
        super().__init__(
            "Failed to serialize message",
            {"messageType": message_type, "format": format, "details": details},
        )


class DeserializationError(EncodingError):
    """Exception raised when message deserialization fails."""

    error_code = "BA702"

    def __init__(
        self,
        message_type: Optional[str] = None,
        raw_data: Optional[str] = None,
        details: Optional[str] = None,
    ):
        super().__init__(
            "Failed to deserialize message",
            {
                "messageType": message_type,
                "rawData": raw_data[:100] + "..." if raw_data else None,
                "details": details,
            },
        )


class CompressionError(EncodingError):
    """Exception raised when compression/decompression fails."""

    error_code = "BA703"

    def __init__(
        self,
        operation: Optional[str] = None,
        data_size: Optional[int] = None,
        details: Optional[str] = None,
    ):
        super().__init__(
            "Failed to compress or decompress data",
            {"operation": operation, "dataSize": data_size, "details": details},
        )


# ============================================================================
# Network Errors (Client-Only)
# ============================================================================


class NetworkError(BetterAuthError):
    """Base exception for network-related errors."""

    error_code = "BA800"


class ConnectionError(NetworkError):
    """Exception raised when connection to server fails."""

    error_code = "BA801"

    def __init__(self, server_url: Optional[str] = None, details: Optional[str] = None):
        super().__init__(
            "Failed to connect to server", {"serverUrl": server_url, "details": details}
        )


class TimeoutError(NetworkError):
    """Exception raised when request times out."""

    error_code = "BA802"

    def __init__(self, timeout_duration: Optional[int] = None, endpoint: Optional[str] = None):
        super().__init__(
            "Request timed out", {"timeoutDuration": timeout_duration, "endpoint": endpoint}
        )


class ProtocolError(NetworkError):
    """Exception raised for HTTP protocol violations."""

    error_code = "BA803"

    def __init__(self, http_status_code: Optional[int] = None, details: Optional[str] = None):
        super().__init__(
            "Invalid HTTP response or protocol violation",
            {"httpStatusCode": http_status_code, "details": details},
        )


# ============================================================================
# Protocol Errors
# ============================================================================


class InvalidStateError(BetterAuthError):
    """Exception raised when operation not allowed in current state."""

    error_code = "BA901"

    def __init__(
        self,
        current_state: Optional[str] = None,
        attempted_operation: Optional[str] = None,
        required_state: Optional[str] = None,
    ):
        super().__init__(
            "Operation not allowed in current state",
            {
                "currentState": current_state,
                "attemptedOperation": attempted_operation,
                "requiredState": required_state,
            },
        )


class RotationError(BetterAuthError):
    """Exception raised when key rotation fails."""

    error_code = "BA902"

    def __init__(self, rotation_type: Optional[str] = None, details: Optional[str] = None):
        super().__init__("Key rotation failed", {"rotationType": rotation_type, "details": details})


class RecoveryError(BetterAuthError):
    """Exception raised when account recovery fails."""

    error_code = "BA903"

    def __init__(self, details: Optional[str] = None):
        super().__init__("Account recovery failed", {"details": details})


class DeviceRevokedError(BetterAuthError):
    """Exception raised when device has been revoked."""

    error_code = "BA904"

    def __init__(
        self, device_identifier: Optional[str] = None, revocation_timestamp: Optional[str] = None
    ):
        super().__init__(
            "Device has been revoked",
            {"deviceIdentifier": device_identifier, "revocationTimestamp": revocation_timestamp},
        )


class IdentityDeletedError(BetterAuthError):
    """Exception raised when identity has been deleted."""

    error_code = "BA905"

    def __init__(
        self, identity_identifier: Optional[str] = None, deletion_timestamp: Optional[str] = None
    ):
        super().__init__(
            "Identity has been deleted",
            {"identityIdentifier": identity_identifier, "deletionTimestamp": deletion_timestamp},
        )


# ============================================================================
# Specialized Errors (for specific operations)
# ============================================================================


class InvalidForwardSecretError(InvalidHashError):
    """Exception raised when rotation hash doesn't match."""

    def __init__(self, provided: Optional[str] = None, expected: Optional[str] = None):
        super().__init__(expected, provided, "forward-secret")
        self.args = ("Invalid forward secret (rotation hash mismatch)",)


class RecoveryHashMismatchError(InvalidHashError):
    """Exception raised when recovery key hash doesn't match."""

    def __init__(self, provided: Optional[str] = None, expected: Optional[str] = None):
        super().__init__(expected, provided, "recovery")
        self.args = ("Recovery key hash does not match stored hash",)


class DuplicateIdentityError(AlreadyExistsError):
    """Exception raised when identity already registered."""

    def __init__(self, identity: Optional[str] = None):
        super().__init__("identity", identity)
        self.args = ("Identity already registered",)


class DuplicateDeviceError(AlreadyExistsError):
    """Exception raised when device already exists."""

    def __init__(self, device: Optional[str] = None):
        super().__init__("device", device)
        self.args = ("Device already exists",)


class InvalidRecoveryKeyError(AuthenticationError):
    """Exception raised when recovery key verification fails."""

    def __init__(self, details: Optional[str] = None):
        super().__init__("Recovery key verification failed", {"details": details})


class ValueReservedError(StorageError):
    """Exception raised when value is currently reserved."""

    def __init__(self, value: Optional[str] = None, reserved_until: Optional[str] = None):
        super().__init__(
            "Value is currently reserved", {"value": value, "reservedUntil": reserved_until}
        )


class InvalidStateTransitionError(InvalidStateError):
    """Exception raised for invalid state transitions."""

    def __init__(self, operation: Optional[str] = None, reason: Optional[str] = None):
        message = f"Invalid state transition: {operation}"
        if reason:
            message += f" ({reason})"
        super().__init__(None, operation, None)
        self.args = (message,)
        self.context = {"operation": operation, "reason": reason}


# Maintain backwards compatibility - alias old names
VerificationError = SignatureVerificationError
InvalidNonceError = IncorrectNonceError
