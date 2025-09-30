"""Identity verification implementation.

This module provides identity verification using Blake3 hashing to verify
that an identity matches its constituent parts (public key, rotation hash,
and optional extra data).
"""

from better_auth.interfaces.crypto import IHasher
from better_auth.interfaces.encoding import IIdentityVerifier

from ..crypto import Hasher


class IdentityVerifier(IIdentityVerifier):
    """Identity verifier using Blake3 hashing.

    This class verifies identities by computing a Blake3 hash of the concatenated
    public key, rotation hash, and optional extra data, then comparing it with
    the provided identity hash.

    The verification process:
    1. Concatenate public_key + rotation_hash + extra_data (if provided)
    2. Compute Blake3 hash of the concatenated string
    3. Compare the computed hash with the provided identity
    4. Raise an exception if they don't match

    Attributes:
        hasher: The Blake3 hasher instance used for computing hashes.
    """

    def __init__(self) -> None:
        """Initialize the identity verifier with a Blake3 hasher."""
        self.hasher: IHasher = Hasher()

    async def verify(
        self,
        identity: str,
        public_key: str,
        rotation_hash: str,
        extra_data: str | None = None,
    ) -> None:
        """Verify an identity with its public key and rotation hash.

        Computes the expected identity hash by hashing the concatenation of
        public_key, rotation_hash, and extra_data (if provided), then compares
        it with the provided identity.

        Args:
            identity: The identity hash to verify.
            public_key: The public key associated with the identity.
            rotation_hash: The rotation hash for key rotation.
            extra_data: Optional extra data to include in the hash.

        Raises:
            Exception: When verification fails (computed hash != identity).

        Example:
            >>> verifier = IdentityVerifier()
            >>> # Assuming we have valid identity components:
            >>> await verifier.verify(
            ...     identity="Eabc123...",
            ...     public_key="Bxyz789...",
            ...     rotation_hash="Edef456...",
            ...     extra_data="session-123"
            ... )
        """
        # Build the suffix from extra_data if provided
        suffix = ""
        if extra_data is not None:
            suffix = extra_data

        # Compute the identity hash from the constituent parts
        identity_hash = await self.hasher.sum(public_key + rotation_hash + suffix)

        # Verify that the computed hash matches the provided identity
        if identity_hash != identity:
            raise Exception("could not verify identity")
