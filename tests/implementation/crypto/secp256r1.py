"""ECDSA P-256 (secp256r1) implementation.

This module provides verifier and signing key implementations for the
ECDSA P-256 elliptic curve using SHA-256 for hashing.
"""

import base64
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.backends import default_backend

from better_auth.interfaces.crypto import ISigningKey, IVerifier


class Secp256r1Verifier(IVerifier):
    """ECDSA P-256 signature verifier.

    Verifies signatures created with ECDSA using the P-256 curve and SHA-256.
    Expects CESR-encoded public keys (prefix: "1AAI") and signatures (prefix: "0I").
    """

    @property
    def signature_length(self) -> int:
        """The expected length of CESR-encoded signatures.

        Returns:
            The signature length (88 characters).
        """
        return 88

    async def verify(self, message: str, signature: str, public_key: str) -> None:
        """Verify a signature against a message using a public key.

        Args:
            message: The message that was signed.
            signature: The CESR-encoded signature (prefix "0I").
            public_key: The CESR-encoded public key (prefix "1AAI").

        Raises:
            ValueError: When verification fails or inputs are invalid.
        """
        try:
            public_key_b64 = public_key[4:]  # Remove "1AAI" prefix
            padding = "=" * ((4 - len(public_key_b64) % 4) % 4)
            public_key_bytes = base64.urlsafe_b64decode(public_key_b64 + padding)

            public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key_bytes
            )

            padding = "=" * ((4 - len(signature) % 4) % 4)
            signature_full = base64.urlsafe_b64decode(signature + padding)

            # Skip first 2 bytes (padding from CESR encoding)
            raw_signature = signature_full[2:]

            # Convert raw 64-byte signature (r || s) to ASN.1 DER format
            if len(raw_signature) != 64:
                raise ValueError(
                    f"invalid signature length: expected 64 bytes, got {len(raw_signature)}"
                )

            r = int.from_bytes(raw_signature[:32], byteorder="big")
            s = int.from_bytes(raw_signature[32:], byteorder="big")
            der_signature = encode_dss_signature(r, s)

            message_bytes = message.encode("utf-8")
            public_key_obj.verify(
                der_signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as e:
            raise ValueError("invalid signature") from e


class Secp256r1(ISigningKey):
    """ECDSA P-256 signing key.

    Generates and manages ECDSA key pairs using the P-256 curve.
    Produces CESR-encoded signatures (prefix: "0I") and public keys (prefix: "1AAI").
    """

    def __init__(self) -> None:
        """Initialize the signing key."""
        self._key_pair: Optional[ec.EllipticCurvePrivateKey] = None
        self._verifier = Secp256r1Verifier()

    async def generate(self) -> None:
        """Generate a new ECDSA P-256 key pair.

        Raises:
            Exception: If key generation fails.
        """
        self._key_pair = ec.generate_private_key(ec.SECP256R1(), default_backend())

    async def sign(self, message: str) -> str:
        """Sign a message with the private key.

        Args:
            message: The message to sign.

        Returns:
            A CESR-encoded signature string starting with "0I".

        Raises:
            ValueError: If the key pair has not been generated.
        """
        if self._key_pair is None:
            raise ValueError("keypair not generated")

        # Encode message as UTF-8
        message_bytes = message.encode("utf-8")

        # Sign the message (returns ASN.1 DER-encoded signature)
        der_signature = self._key_pair.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256()),
        )

        # Decode ASN.1 DER signature to get raw r and s values
        r, s = decode_dss_signature(der_signature)

        # Convert r and s to 32-byte big-endian format (raw 64-byte signature)
        r_bytes = r.to_bytes(32, byteorder="big")
        s_bytes = s.to_bytes(32, byteorder="big")
        signature_bytes = r_bytes + s_bytes

        # Pad with 2 zero bytes at the beginning for CESR encoding
        padded = bytes([0, 0]) + signature_bytes
        base64_str = base64.urlsafe_b64encode(padded).decode("ascii").rstrip("=")

        # Remove the first 2 characters (from padding) and add CESR prefix
        return f"0I{base64_str[2:]}"

    async def public(self) -> str:
        """Get the public key.

        Returns:
            A CESR-encoded public key string starting with "1AAI".

        Raises:
            ValueError: If the key pair has not been generated.
        """
        if self._key_pair is None:
            raise ValueError("keypair not generated")

        # Export the public key in uncompressed format
        public_key_obj = self._key_pair.public_key()
        uncompressed = public_key_obj.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Compress the public key
        compressed = self._compress_public_key(uncompressed)

        # Pad with 3 zero bytes at the beginning for CESR encoding
        padded = bytes([0, 0, 0]) + compressed
        base64_str = base64.urlsafe_b64encode(padded).decode("ascii").rstrip("=")

        # Remove the first 4 characters (from padding) and add CESR prefix
        return f"1AAI{base64_str[4:]}"

    def verifier(self) -> IVerifier:
        """Return the algorithm verifier.

        Returns:
            The Secp256r1Verifier instance.
        """
        return self._verifier

    async def verify(self, message: str, signature: str) -> None:
        """Verify a signature using the verifier and public key.

        This is a convenience method that uses the internal verifier.

        Args:
            message: The message that was signed.
            signature: The signature to verify.

        Raises:
            ValueError: When verification fails.
        """
        public_key = await self.public()
        await self._verifier.verify(message, signature, public_key)

    def _compress_public_key(self, uncompressed_key: bytes) -> bytes:
        """Compress an uncompressed P-256 public key.

        Args:
            uncompressed_key: The uncompressed public key (65 bytes).

        Returns:
            The compressed public key (33 bytes).

        Raises:
            ValueError: If the key has invalid length or format.
        """
        if len(uncompressed_key) != 65:
            raise ValueError("invalid length")

        if uncompressed_key[0] != 0x04:
            raise ValueError("invalid byte header")

        # Extract x and y coordinates
        x = uncompressed_key[1:33]
        y = uncompressed_key[33:65]

        # Determine y parity (even/odd)
        y_parity = y[31] & 1
        prefix = 0x02 if y_parity == 0 else 0x03

        # Create compressed key: prefix byte + x coordinate
        compressed_key = bytes([prefix]) + x

        return compressed_key
