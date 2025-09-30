# better-auth-py

Python implementation of [better-auth](https://github.com/jasoncolburne/better-auth) - an agnostic authentication framework.

Better-auth is designed to be agnostic of encoding, cryptographic choice, and storage mechanism. It simply composes cryptographic and storage interfaces that you provide. In-memory/software examples exist in the test directory.

Disclaimer: Anthropic's Claude wrote this whole readme and library, porting it from the
[typescript](https://github.com/jasoncolburne/better-auth-ts) implementation.

## Features

- **Agnostic Design**: Bring your own cryptography, storage, and encoding implementations
- **Protocol Interfaces**: Clean separation between protocol and implementation
- **Type Safe**: Full type hints using Python's typing system
- **Async First**: Built with async/await throughout
- **Comprehensive**: Includes client, server, and access verification components
- **Well Tested**: Complete test suite covering all authentication flows

## Installation

```bash
# Install from source
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

See `tests/test_api.py` for complete examples of client-server integration.

### Basic Usage

```python
from better_auth import BetterAuthClient, BetterAuthServer
from better_auth.interfaces import IHasher, INetwork, ISigningKey
# ... import your crypto, storage, and encoding implementations

# Configure client
client = BetterAuthClient({
    "crypto": {
        "hasher": your_hasher,
        "noncer": your_noncer,
        "response_public_key": server_public_key,
    },
    "encoding": {"timestamper": your_timestamper},
    "io": {"network": your_network},
    "paths": your_paths,
    "store": {
        "identity": your_identity_store,
        "device": your_device_store,
        "key": {
            "authentication": your_auth_key_store,
            "access": your_access_key_store,
        },
        "token": {"access": your_token_store},
    },
})

# Configure server
server = BetterAuthServer({
    "crypto": {
        "hasher": your_hasher,
        "key_pair": {
            "response": response_signing_key,
            "access": access_signing_key,
        },
        "verifier": your_verifier,
    },
    "encoding": {
        "identity_verifier": your_identity_verifier,
        "timestamper": your_timestamper,
        "token_encoder": your_token_encoder,
    },
    "expiry": {
        "access_in_minutes": 15,
        "refresh_in_hours": 24,
    },
    "store": {
        "access": {"key_hash": your_access_key_hash_store},
        "authentication": {
            "key": your_auth_key_store,
            "nonce": your_nonce_store,
        },
        "recovery": {"hash": your_recovery_hash_store},
    },
})

# Use client
await client.create_account(recovery_hash)
await client.authenticate()
response = await client.make_access_request("/api/endpoint", {"data": "value"})
```

## Architecture

### Interfaces

The `better_auth.interfaces` package defines protocols for:

- **Crypto**: `IHasher`, `INoncer`, `IVerifier`, `ISigningKey`, `IVerificationKey`
- **Encoding**: `ITimestamper`, `ITokenEncoder`, `IIdentityVerifier`
- **Storage**: Client and server stores for keys, tokens, nonces, recovery
- **I/O**: `INetwork` for client-server communication
- **Paths**: `IAuthenticationPaths` for endpoint configuration

### Messages

The `better_auth.messages` package provides protocol message types:

- **Base**: `SerializableMessage`, `SignableMessage`, `ClientRequest`, `ServerResponse`
- **Account**: `CreationRequest/Response`, `RecoverAccountRequest/Response`
- **Linking**: `LinkContainer`, `LinkDeviceRequest/Response`
- **Authentication**: `StartAuthenticationRequest/Response`, `FinishAuthenticationRequest/Response`
- **Rotation**: `RotateAuthenticationKeyRequest/Response`
- **Access**: `AccessToken`, `AccessRequest`, `RefreshAccessTokenRequest/Response`

### API Components

- **BetterAuthClient**: Client-side authentication operations
- **BetterAuthServer**: Server-side authentication handling
- **AccessVerifier**: Standalone access token verification

## Reference Implementations

The `tests/implementation/` directory contains reference implementations:

- **Crypto**: Blake3 hashing, ECDSA P-256 signing/verification, nonce generation
- **Encoding**: RFC3339 timestamps, gzip token compression, identity verification
- **Storage**: In-memory stores for testing

These implementations use:
- `blake3` for cryptographic hashing
- `cryptography` for ECDSA P-256
- `secrets` for secure random number generation
- Standard library modules for encoding

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=better_auth

# Run specific test
pytest tests/test_api.py::test_completes_auth_flows

# Run with verbose output
pytest -v
```

## Authentication Flows

### Account Creation
1. Client generates authentication keypair + identity
2. Client sends identity, device, public key, rotation hash, recovery hash
3. Server stores authentication key and recovery hash

### Two-Phase Authentication
1. **Start**: Client requests challenge nonce for identity
2. **Finish**: Client signs challenge, provides access keypair
3. Server issues access token with custom attributes

### Access Requests
1. Client signs request with access key, includes access token
2. Server verifies token & signature, extracts identity + attributes
3. Nonce prevents replay attacks

### Token Refresh
1. Client rotates access keypair, signs with old access key
2. Server validates rotation hash chain, issues new token

### Key Rotation
1. Client rotates authentication keypair
2. Server validates rotation hash chain

### Device Linking
1. New device generates keypair + link container
2. Existing device endorses link container
3. Server validates both signatures

### Account Recovery
1. Client signs with recovery key
2. Server validates against stored recovery hash
3. Client establishes new authentication keypair

## Project Structure

```
better-auth-py/
├── better_auth/
│   ├── __init__.py           # Main package exports
│   ├── exceptions.py         # Exception types
│   ├── api/                  # Client/server/verifier
│   ├── interfaces/           # Protocol definitions
│   └── messages/             # Message types
├── tests/
│   ├── test_api.py           # API integration tests
│   └── implementation/       # Reference implementations
├── pyproject.toml
└── README.md
```

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run type checking
mypy better_auth

# Format code
black better_auth tests

# Lint
ruff check better_auth tests
```

## License

MIT

## Related Implementations

- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Go](https://github.com/jasoncolburne/better-auth-go) - Go implementation
