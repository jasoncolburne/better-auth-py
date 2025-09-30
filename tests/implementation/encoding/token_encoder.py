"""Token compression and encoding implementation.

This module provides token encoding/decoding with gzip compression and base64url
encoding, matching the TypeScript implementation using Pako.
"""

import gzip

from better_auth.interfaces.encoding import ITokenEncoder

from .base64 import Base64


class TokenEncoder(ITokenEncoder):
    """Token encoder that compresses and encodes tokens.

    This class implements token encoding by:
    1. Converting the input string to UTF-8 bytes
    2. Compressing with gzip at maximum compression level (9)
    3. Encoding with base64url
    4. Removing padding '=' characters

    Decoding reverses this process:
    1. Restoring padding '=' characters
    2. Decoding from base64url
    3. Decompressing with gzip
    4. Converting UTF-8 bytes back to string
    """

    async def encode(self, object: str) -> str:
        """Encode an object string into a compressed and encoded token.

        The encoding process:
        1. Encode the string to UTF-8 bytes
        2. Compress using gzip with maximum compression (level 9)
        3. Encode to base64url
        4. Remove padding '=' characters

        Args:
            object: The object string to encode.

        Returns:
            The compressed and encoded token string without padding.

        Example:
            >>> encoder = TokenEncoder()
            >>> token = await encoder.encode('{"user": "alice", "role": "admin"}')
            >>> isinstance(token, str)
            True
        """
        # Convert string to UTF-8 bytes
        token_bytes = object.encode('utf-8')

        # Compress with gzip at maximum compression level (9)
        compressed_token = gzip.compress(token_bytes, compresslevel=9)

        # Encode to base64url and remove padding
        token = Base64.encode(compressed_token).replace('=', '')

        return token

    async def decode(self, raw_token: str) -> str:
        """Decode a compressed and encoded token back to the original string.

        The decoding process:
        1. Restore padding '=' characters (base64 requires length % 4 == 0)
        2. Decode from base64url
        3. Decompress using gzip
        4. Convert UTF-8 bytes to string

        Args:
            raw_token: The raw token string to decode.

        Returns:
            The decoded and decompressed object string.

        Raises:
            gzip.BadGzipFile: If the token is not valid gzip data.
            UnicodeDecodeError: If the decompressed data is not valid UTF-8.

        Example:
            >>> encoder = TokenEncoder()
            >>> token = await encoder.encode('{"user": "alice"}')
            >>> original = await encoder.decode(token)
            >>> original
            '{"user": "alice"}'
        """
        token = raw_token

        # Restore padding (base64 strings must have length divisible by 4)
        while len(token) % 4 != 0:
            token += '='

        # Decode from base64url
        compressed_token = Base64.decode(token)

        # Decompress with gzip
        object_bytes = gzip.decompress(compressed_token)

        # Convert UTF-8 bytes to string
        object_string = object_bytes.decode('utf-8')

        return object_string