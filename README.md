# better-auth-py

**Python implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This is a full Python port of the TypeScript reference implementation with both client and server components.

## What's Included

- ✅ **Client + Server** - Full protocol implementation
- ✅ **Type-Safe** - Comprehensive type hints using Python's typing system
- ✅ **Async First** - Built with async/await throughout
- ✅ **Complete Test Suite** - Unit tests covering all authentication flows
- ✅ **Example Server** - HTTP server for integration testing

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # Create venv and install dependencies
```

### Running Tests

```bash
make test           # Run pytest
make type-check     # Run mypy type checker
make lint           # Run ruff linter
make format-check   # Check code formatting
```

### Running Example Server

```bash
make server         # Start HTTP server on localhost:8080
```

## Development

This implementation uses:
- **Python 3.11+** for modern type hints and async support
- **pytest** for testing
- **mypy** for type checking
- **black** for formatting
- **ruff** for linting

All development commands use standardized `make` targets:

```bash
make setup          # Create venv and pip install -e ".[dev]"
make test           # Run pytest
make type-check     # Type check with mypy
make lint           # Lint with ruff
make format         # Format with black
make format-check   # Check formatting
make clean          # Remove venv and build artifacts
make server         # Run example server
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- Python-specific patterns (Protocol types, dataclasses, async/await)
- Interface definitions and message types
- Usage examples and API patterns

### Key Features

- **Protocol Types**: Uses Python's `Protocol` type for structural subtyping
- **Dataclasses**: All messages defined as `@dataclass` with type hints
- **Async Throughout**: All operations use Python's `async`/`await`
- **Custom Exceptions**: `BetterAuthError`, `AuthenticationError`, `VerificationError`, etc.

### Reference Implementations

The `tests/implementation/` directory contains reference implementations using:
- **blake3** for cryptographic hashing
- **cryptography** library for ECDSA P-256 signing/verification
- **secrets** module for secure random nonce generation
- **datetime** for RFC3339 timestamps
- **gzip** for token compression

## Integration with Other Implementations

This Python implementation can be used:
- As a **client** for testing against TypeScript, Rust, Go, or Ruby servers
- As a **server** for testing TypeScript, Python, Rust, Swift, Dart, or Kotlin clients

See `examples/server.py` for the HTTP server implementation.

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Python](https://github.com/jasoncolburne/better-auth-py) - **This repository**
- [Rust](https://github.com/jasoncolburne/better-auth-rs)

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go)
- [Ruby](https://github.com/jasoncolburne/better-auth-rb)

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift)
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## License

MIT
