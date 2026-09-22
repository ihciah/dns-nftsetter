# dns-nftsetter

`dns-nftsetter` is a high-performance Linux daemon written in Rust that sniffs DNS traffic, parses resolved IPv4 addresses from DNS response packets (`A` and `CNAME` records), and dynamically updates `nftables` sets using direct Netlink communication.

It is designed to enable domain-specific and client-specific routing policies (e.g., policy routing, split-tunneling, or selective proxying) on Linux-based routers/gateways.

## Features

- **Direct Netlink Client**: Communicates directly with the Linux kernel netfilter subsystem over raw Netlink sockets (`libc`). No dependency on external command line tools (`nft`) or C FFI libraries (`libnftables`, `libnftnl`), making it highly portable and easy to build.
- **Low-Overhead Packet Sniffing**: Uses `libpcap` to capture incoming DNS UDP responses (port 53) utilizing kernel-level BPF filtering (`udp src port 53`) to keep resource utilization to a minimum.
- **Suffix Wildcard Domain Matching**: Employs an efficient reversed label Trie structure to match domains. For example, a rule for `apple.com` will match both `apple.com` and subdomains like `*.apple.com` (e.g., `www.apple.com`, `init.push.apple.com`).
- **CNAME Chain Resolving & Filtering**:
  - Traverses nested `CNAME` chains to associate resolved IPs back to the original queried domain name.
  - **Lazy Association Filtering**: To prevent caching unrelated domains, it only caches CNAME mappings that trace back to your configured rules.
- **Clamped Expiration & Refresh**:
  - CNAME cache mappings expire based on their record TTL.
  - TTL values are clamped to a safe range (minimum 1 minute, maximum 1 day) to avoid memory exhaustion from malformed packets.
  - Expired mappings are lazily dropped on access. Active mappings are automatically refreshed on query matches to keep active connections alive.
- **Dry-Run & Verbose Modes**:
  - `--dry-run` allows you to test matching logic and log additions without modifying your active nftables sets.
  - `--verbose` enables detailed debug logging.
- **Structured Logging**: Uses `tracing` and `tracing-subscriber` for clean, structured, and timestamped console logging.

## Architecture

```text
                      +-----------------------------+
                      |     libpcap DNS Sniffer     |
                      +--------------+--------------+
                                     | (Raw UDP Responses)
                                     v
                      +-----------------------------+
                      |      Packet Parser          |
                      +--------------+--------------+
                                     | (Client IP, DNS Answers)
                                     v
                      +-----------------------------+
                      |   CNAME Cache & Matcher     | <--- Trie Ruleset Config
                      +--------------+--------------+
                                     | (Matched IP/IP-Pair & TTL)
                                     v
                      +-----------------------------+
                      |   Netlink Batch Executor    |
                      +--------------+--------------+
                                     | (Netlink Msg)
                                     v
                      +-----------------------------+
                      |  Linux Kernel (nf_tables)   |
                      +-----------------------------+
```

## Configuration Format

The configuration file is formatted as one rule per line. Each line has the format:

```text
<source_pattern> / <domain> / <nftables_set_name>
```

- **Client-Specific Pair Rules**:
  `192.168.1.100/apple.com/pair_dynamic`
  Only DNS queries coming from `192.168.1.100` that resolve domains matching `*.apple.com` will trigger adding the element to the pair set `pair_dynamic`. Elements are added as `client_ip . resolved_ip` (type `ipv4_addr . ipv4_addr`).
- **Any-Client Pair Rules**:
  `*/google.com/pair_dynamic`
  DNS queries from *any* client resolving domains matching `*.google.com` will trigger adding the element `client_ip . resolved_ip` to `pair_dynamic`.
- **Global Single IP Rules**:
  `*!/fb.com/global_dynamic`
  DNS queries from any client resolving domains matching `*.fb.com` will trigger adding the resolved IP directly to the single IP set `global_dynamic` (type `ipv4_addr`), affecting all clients globally.

## Build

To build the project, you need the Rust toolchain and `libpcap` installed.

### Using Nix Flakes (Modern Nix)

You can build the package or start a development shell with native Nix Flakes:

```bash
# Build the default package (produces ./result/bin/dns-nftsetter)
nix build

# Start a development shell with rustc, cargo, pkg-config, and libpcap
nix develop
```

### Using Traditional Nix

If you prefer classic Nix:

```bash
# Build the package (produces ./result/bin/dns-nftsetter)
nix-build default.nix

# Enter the nix-shell environment
nix-shell
```

### Nix Binary Cache

Pushes to `main` automatically build and publish the Nix package for
`x86_64-linux` and `aarch64-linux` to `https://nix-cache.ihc.im`. The workflow
checks out the latest `master` version of the cache's staging-upload client,
uploads NAR payloads through temporary R2 staging keys, and publishes narinfo
metadata only after those uploads complete. It also supports manual dispatch
with `dev`, `rc`, or `prod` cache channels.

For a local publish, provide the cache write token and signing key through the
environment, then run:

```bash
NIX_CACHE_PASSWORD="$NIX_CACHE_WRITE_TOKEN" \
  NIX_CACHE_SECRET_KEY_FILE="$HOME/.config/nix/cache-signing-key.sec" \
  scripts/build-and-push-nix-cache.sh
```

The publishing script creates temporary credential and registration files and
does not store cache credentials in the repository.

### Standard Cargo

On other Linux distributions (ensure `libpcap-dev` / `libpcap` headers are installed):

```bash
cargo build --release
```

### Docker

To build the Docker container:

```bash
docker build -t dns-nftsetter .
```

---

## Usage

```bash
sudo ./target/release/dns-nftsetter [OPTIONS] --config <CONFIG_PATH>
```

### Command Line Options

- `-i, --interface <INTERFACE>`: Interface to sniff on (e.g., `eth0`, `any`). Defaults to `any`.
- `-c, --config <CONFIG>`: Path to the configuration rules file (Required).
- `-t, --table <TABLE>`: Target nftables table name. Defaults to `filter`.
- `-f, --family <FAMILY>`: Target nftables table family (`ip` or `inet`). Defaults to `ip`.
- `-d, --default-timeout <TIMEOUT>`: Default timeout in seconds for DNS records that return a TTL of 0. Defaults to `10`.
- `-b, --batch-limit <LIMIT>`: Maximum number of nftables elements per batch flush. Defaults to `128`.
- `--cname-capacity <CAPACITY>`: Maximum capacity of the bounded CNAME cache. Defaults to `1000`.
- `--filter-dst-ip <IP>`: Optional IPv4 address to filter captured packet's destination IP (client IP).
- `--dry-run`: Enable dry-run mode. Matching DNS entries are logged but netlink updates to the kernel sets are skipped.
- `-v, --verbose`: Enable verbose logging to output debug level traces.

### Running via Docker Compose

Because the daemon needs to capture raw packet traffic on host interfaces and update host `nftables` via Netlink, the container must be run with the host network and elevated system capabilities:

1. Create a `rules.conf` file (see `rules.conf.example` for details).
2. Create the corresponding nftables sets on the host.
3. Start the container:

   ```bash
   docker-compose up -d
   ```

### Example Run

Create a config file at `/etc/dns-nftsetter.conf`:

```text
192.168.1.100 / apple.com / pair_dynamic
* / google.com / pair_dynamic
*! / fb.com / global_dynamic
```

Create the corresponding nftables sets:

```bash
nft add table ip filter
nft add set ip filter pair_dynamic { type ipv4_addr . ipv4_addr; flags timeout; }
nft add set ip filter global_dynamic { type ipv4_addr; flags timeout; }
```

Run the daemon:

```bash
sudo ./target/release/dns-nftsetter -i any -c /etc/dns-nftsetter.conf -t filter -f ip --verbose
```

---

## License

This project is dual-licensed under:

- **MIT License** ([LICENSE-MIT](./LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE))
