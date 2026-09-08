# SimplePortScanner

A fast, multithreaded TCP and UDP port scanner written in C++23 with service name resolution and TCP banner grabbing.

## Features

- **Multithreaded Scanning**: Distributes port scanning tasks across available hardware threads using `std::jthread` and `std::stop_token`.
- **Protocol Support**: Supports both TCP connect scanning and UDP probe scanning.
- **Service Name Resolution**: Automatically resolves known service names for open ports using system service databases (`getservbyport`).
- **Banner Grabbing**: Captures application response banners or sends HTTP probes to identify services.
- **INI Configuration**: Easily configure scan parameters via `scanner.ini` powered by `SQRLL_INI_Reader`.
- **CLI Overrides**: Override configuration values on the fly with command-line arguments.

## Requirements

- **C++ Compiler**: Supporting C++23 (e.g., GCC 13+, Clang 16+)
- **CMake**: Version 3.14 or higher
- **POSIX-compliant OS**: Linux, macOS, or BSD (uses POSIX socket and poll APIs)
- **Threads library**: `pthread` (handled automatically by CMake)

## Building the Project

1. Clone or navigate to the repository directory:
   ```bash
   cd SimplePortScanner
   ```

2. Create a build directory and configure CMake:
   ```bash
   cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
   ```

3. Build the `port_scanner` executable:
   ```bash
   cmake --build build --target port_scanner
   ```

## Configuration (`scanner.ini`)

The scanner automatically loads default settings from `scanner.ini` in the working directory if present.

### Example `scanner.ini`

```ini
# SimplePortScanner Configuration File
# Comments start with '#'

# Target IPv4 address to scan
targetIp = 127.0.0.1

# Port range to scan
startPort = 1
endPort = 1024

# Connection timeouts in milliseconds
tcpTimeoutMs = 200
udpTimeoutMs = 500

# Protocols to scan (true / false)
scanTcp = true
scanUdp = false
```

### Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `targetIp` | string | `127.0.0.1` | Target IPv4 address to scan |
| `startPort` | integer | `1` | First port in the scanning range |
| `endPort` | integer | `1024` | Last port in the scanning range |
| `tcpTimeoutMs` | integer | `200` | Connection timeout for TCP probes (in ms) |
| `udpTimeoutMs` | integer | `500` | Response timeout for UDP probes (in ms) |
| `scanTcp` | boolean | `true` | Enable or disable TCP scanning |
| `scanUdp` | boolean | `false` | Enable or disable UDP scanning |

## Usage & Command-Line Arguments

Run the compiled executable directly:

```bash
./port_scanner
```

You can override configuration parameters via command-line flags:

| Argument | Description | Example |
| :--- | :--- | :--- |
| `-IP:<address>` | Sets target IPv4 address | `./port_scanner -IP:192.168.1.1` |
| `-TCP` | Enables TCP scanning | `./port_scanner -TCP` |
| `-UDP` | Enables UDP scanning | `./port_scanner -UDP` |
| `-TCP_TIME=<ms>` | Sets TCP probe timeout in milliseconds | `./port_scanner -TCP_TIME=300` |
| `-UDP_TIME=<ms>` | Sets UDP probe timeout in milliseconds | `./port_scanner -UDP_TIME=500` |

### Combined Example

```bash
./port_scanner -IP:127.0.0.1 -TCP -UDP -TCP_TIME=100 -UDP_TIME=200
```

### Sample Output

```text
Starting scan on 127.0.0.1...
Protocols: TCP UDP
Timeouts: TCP=100ms, UDP=200ms
[+] Port 22/TCP is OPEN|FILTERED (ssh) -> Banner: [SSH-2.0-OpenSSH_10.2  ]
[+] Port 80/TCP is OPEN|FILTERED (http) -> Banner: [HTTP/1.1 200 OK  Date: Tue, 08 Sep 2026 06:42:30 GMT  Ser...]
[+] Port 323/UDP is OPEN|FILTERED (unknown)
[+] Port 631/TCP is OPEN|FILTERED (ipp) -> Banner: [HTTP/1.0 400 Bad Request  Content-Language: en_US  Conten...]
```
