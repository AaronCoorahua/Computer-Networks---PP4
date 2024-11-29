# Computer-Networks---PP4

## Compilation

To compile the program, use the provided `Makefile`:

1. Open a terminal and navigate to the project directory.
2. Run the `make` command:

```bash
make
```

## Usage

Run the program with superuser privileges (using `sudo`) to allow access to raw sockets.

### Basic Syntax

```bash
sudo ./traceroute -d [destination IP] -v [verbosity level]
```
### Examples

#### 1. Tracing Route to a Reachable IP (Google DNS)

```bash
sudo ./traceroute -d 8.8.8.8 -v 3
```

#### 2. Tracing Route to an Unreachable IP

```bash
sudo ./traceroute -d 192.0.2.1 -v 3
```
