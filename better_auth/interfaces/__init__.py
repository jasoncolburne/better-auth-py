"""Better-auth interfaces package.

This package provides protocol definitions for cryptographic operations,
storage, encoding, I/O, and authentication paths.
"""

from .crypto import IHasher, INoncer, ISigningKey, IVerificationKey, IVerifier
from .encoding import IIdentityVerifier, ITimestamper, ITokenEncoder
from .io import INetwork
from .paths import IAuthenticationPaths
from .storage import (
    IClientRotatingKeyStore,
    IClientValueStore,
    IServerAuthenticationKeyStore,
    IServerAuthenticationNonceStore,
    IServerRecoveryHashStore,
    IServerTimeLockStore,
)

__all__ = [
    # crypto
    "IHasher",
    "INoncer",
    "ISigningKey",
    "IVerificationKey",
    "IVerifier",
    # encoding
    "IIdentityVerifier",
    "ITimestamper",
    "ITokenEncoder",
    # io
    "INetwork",
    # paths
    "IAuthenticationPaths",
    # storage
    "IClientRotatingKeyStore",
    "IClientValueStore",
    "IServerAuthenticationKeyStore",
    "IServerAuthenticationNonceStore",
    "IServerRecoveryHashStore",
    "IServerTimeLockStore",
]
