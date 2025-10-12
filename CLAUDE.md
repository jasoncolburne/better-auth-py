# Better Auth - Python Implementation

## Project Context

This is a **Python implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation includes **both client and server** components and was ported from the TypeScript reference implementation.

**Disclaimer:** This library was written by Anthropic's Claude, porting it from the [TypeScript reference implementation](https://github.com/jasoncolburne/better-auth-ts).

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Reference Implementation:** [better-auth-ts](https://github.com/jasoncolburne/better-auth-ts) (TypeScript)

**Other Implementations:**
- Full: [Rust](https://github.com/jasoncolburne/better-auth-rs)
- Server Only: [Go](https://github.com/jasoncolburne/better-auth-go), [Ruby](https://github.com/jasoncolburne/better-auth-rb)
- Client Only: [Swift](https://github.com/jasoncolburne/better-auth-swift), [Dart](https://github.com/jasoncolburne/better-auth-dart), [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## Repository Structure

This repository is a **git submodule** of the parent [better-auth](https://github.com/jasoncolburne/better-auth) specification repository. The parent repository includes all 8 language implementations as submodules and provides orchestration scripts for cross-implementation testing.

### Standardized Build System

All implementations use standardized `Makefile` targets for consistency:

```bash
make setup          # Create venv and install dependencies (pip install -e ".[dev]")
make test           # Run tests (pytest)
make type-check     # Run type checker (mypy better_auth)
make lint           # Run linter (ruff check better_auth tests)
make format         # Format code (black better_auth tests)
make format-check   # Check formatting (black --check better_auth tests)
make clean          # Clean artifacts (rm -rf venv build dist)
make server         # Run example server (python -m examples.server)
```

### Parent Repository Orchestration

The parent repository provides scripts in `scripts/` for running operations across all implementations:

- `scripts/run-setup.sh` - Setup all implementations
- `scripts/run-unit-tests.sh` - Run tests across all implementations
- `scripts/run-type-checks.sh` - Run type checkers across all implementations
- `scripts/run-lints.sh` - Run linters across all implementations
- `scripts/run-format-checks.sh` - Check formatting across all implementations
- `scripts/run-integration-tests.sh` - Run cross-language integration tests
- `scripts/run-all-checks.sh` - Run all checks in sequence
- `scripts/pull-repos.sh` - Update all submodules

These scripts automatically skip implementations where tooling is not available.

## Architecture

### Directory Structure

```
better_auth/
├── __init__.py           # Main package exports
├── exceptions.py         # Exception types
├── api/                  # Client and Server implementations
│   ├── __init__.py
│   ├── client.py         # BetterAuthClient class
│   └── server.py         # BetterAuthServer class
├── interfaces/           # Protocol interfaces
│   ├── __init__.py
│   ├── crypto.py         # Hashing, signing, verification protocols
│   ├── encoding.py       # Timestamping, token encoding, identity verification
│   ├── io.py             # Network protocol
│   ├── paths.py          # Authentication paths protocol
│   └── storage.py        # Client and server storage protocols
└── messages/             # Protocol message types
    ├── __init__.py
    ├── message.py        # Base message types
    ├── request.py        # Base request types
    ├── response.py       # Base response types
    ├── account.py        # Account protocol messages
    ├── device.py         # Device protocol messages
    ├── session.py        # Session protocol messages
    └── access.py         # Access protocol messages

tests/
├── test_api.py           # API integration tests
└── implementation/       # Reference implementations
    ├── crypto.py         # Blake3, ECDSA P-256
    ├── encoding.py       # RFC3339, gzip compression, identity verification
    ├── storage.py        # In-memory stores
    └── network.py        # Mock network implementation

examples/
└── server.py             # Example HTTP server
```

### Key Components

**BetterAuthClient** (`better_auth/api/client.py`)
- Implements all client-side protocol operations
- Manages authentication state and key rotation
- Handles token lifecycle
- Composes crypto, storage, and encoding interfaces

**BetterAuthServer** (`better_auth/api/server.py`)
- Implements all server-side protocol operations
- Validates requests and manages device state
- Issues and validates tokens
- Composes crypto, storage, and encoding interfaces

**Message Types** (`better_auth/messages/`)
- Protocol message dataclasses
- Serialization/deserialization using `to_dict()` and `from_dict()`
- Type-safe request/response pairs

**Interfaces** (`better_auth/interfaces/`)
- Protocol definitions using Python's `Protocol` type
- Define contracts for crypto, storage, encoding, and I/O
- Enable duck-typed implementations

## Python-Specific Patterns

### Protocol Types

This implementation uses Python's `Protocol` type (from `typing`) to define interfaces:
- `IHasher`, `INoncer`, `IVerifier` for crypto
- `ISigningKey`, `IVerificationKey` for keys
- Storage protocols for client and server
- `INetwork`, `ITimestamper`, `ITokenEncoder`, etc.

This provides structural subtyping (duck typing) with type checking support.

### Dataclasses for Messages

All protocol messages are defined as `@dataclass` classes:
- Automatic `__init__`, `__repr__`, etc.
- Type hints for all fields
- Easy serialization with `to_dict()` / `from_dict()` methods

### Async/Await Throughout

All operations are async using Python's `async`/`await`:
- Client operations return `Awaitable[T]`
- Server operations return `Awaitable[ServerResponse]`
- All storage operations are async
- All network operations are async

This mirrors the async nature of the TypeScript reference implementation.

### Type Hints

Comprehensive type hints using Python's typing system:
- Function signatures have full type annotations
- Return types are explicit
- Generic types like `Optional[T]`, `Dict[str, Any]` used throughout

### Exception Handling

Custom exceptions in `exceptions.py`:
- `BetterAuthError` - Base exception
- `AuthenticationError` - Authentication failures
- `VerificationError` - Signature/hash verification failures
- `StorageError` - Storage operation failures
- `EncodingError` - Encoding/decoding failures

## Reference Implementations

The `tests/implementation/` directory contains reference implementations using:
- **blake3** for cryptographic hashing
- **cryptography** library for ECDSA P-256 signing/verification
- **secrets** module for secure random nonce generation
- **datetime** for RFC3339 timestamps
- **gzip** for token compression
- **base64** for encoding

These demonstrate how to implement the protocol interfaces in Python.

## Testing

### Unit Tests (`tests/test_api.py`)
Comprehensive tests covering:
- Account creation, recovery, deletion
- Device linking/unlinking
- Two-phase authentication
- Access requests
- Key rotation (authentication and access)
- Token refresh

Run with: `pytest tests/test_api.py`

### Running Tests
```bash
pytest                         # Run all tests
pytest --cov=better_auth       # With coverage
pytest -v                      # Verbose output
pytest tests/test_api.py::test_completes_auth_flows  # Specific test
```

## Usage Patterns

### Client Initialization

```python
from better_auth import BetterAuthClient

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
```

### Server Initialization

```python
from better_auth import BetterAuthServer

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
```

### Client Operations

```python
# Create account
await client.create_account(recovery_hash)

# Authenticate
await client.authenticate()

# Make access request
response = await client.make_access_request("/api/resource", {"data": "value"})

# Rotate authentication key
await client.rotate_authentication_key()

# Refresh access token
await client.refresh_access_token()
```

### Server Operations

```python
# Handle request
response = await server.handle_request(request)
```

## Development Workflow

### Installation
```bash
# It's recommended to use a virtual environment
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate

pip install -e .              # Install in development mode
pip install -e ".[dev]"       # With dev dependencies
```

### Running the Example Server
```bash
# Make sure you're in the virtual environment
python -m examples.server
```

The example server provides an HTTP endpoint for integration testing with other language implementations.

### Testing
```bash
pytest                        # Run tests
pytest --cov=better_auth      # With coverage
```

### Type Checking
```bash
mypy better_auth              # Type check
```

### Linting & Formatting
```bash
black better_auth tests       # Format code
ruff check better_auth tests  # Lint
```

## Integration with Other Implementations

This Python implementation includes:
- Client for testing against Go/Ruby servers
- Server for testing TypeScript clients

The `examples/server.py` provides an HTTP server for integration testing.

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `pytest`
3. Run type checking: `mypy better_auth`
4. Format code: `black .`
5. If protocol changes: sync with the TypeScript reference implementation
6. If breaking changes: update other implementations that depend on this server
7. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `better_auth/api/client.py` - All client logic
- `better_auth/api/server.py` - All server logic
- `better_auth/messages/` - Protocol message definitions
- `better_auth/interfaces/` - Interface contracts (Protocol types)
- `tests/test_api.py` - Comprehensive test suite
- `tests/implementation/` - Reference implementations of interfaces
- `examples/server.py` - Example HTTP server

## Python Version

Requires Python 3.11+ for:
- Modern type hints
- `Protocol` type support
- Async/await improvements
