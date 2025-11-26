# KSH

KSH is a powerful remote control and penetration testing toolkit designed with a client-server architecture, focusing on covert communication and modular extensibility. It is particularly suitable for various embedded and small devices due to its lightweight client implementation.

## Architecture Overview

The system adopts a layered architecture design, mainly consisting of the following core components:

- **Server Daemon** - Responsible for listening to connections, managing sessions, and processing commands
- **Controlled Client** - Deployed on target systems to execute instructions from the server
- **Encryption Communication Layer** - Secure communication mechanism based on PEL protocol
- **Plugin System** - Supports functional extensions such as intranet scanning and socks5 proxy

## Build Instructions

The project uses Makefile for building and supports multiple platforms:

```bash
# Automatically detect platform and build
make

# Or specify a specific platform
make linux              # Linux dynamic linked version
make linux-static       # Linux static linked version
make freebsd            # FreeBSD dynamic linked version
make freebsd-static     # FreeBSD static linked version
make cygwin             # Cygwin version
```

Build artifacts are located in the build directory:

- `build/server` - Server daemon process
- `build/client` - Controlled client
- `plugins/lib/` - Various functional plugins

## License

This project is for authorized security testing purposes only. Please comply with local laws and regulations. It may not be used for illegal purposes without authorization.
