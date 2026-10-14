# L7wall

[![CI](https://github.com/KDOL9/L7wall/actions/workflows/ci.yml/badge.svg)](https://github.com/KDOL9/L7wall/actions/workflows/ci.yml)

A small next-generation firewall engine in modern C++ (C++23), built from scratch to explore
how real NGFW / DPI data planes work: packet decoding, connection tracking, L7 protocol
identification and policy enforcement.

## Status

Stage 1 — offline analysis of pcap captures:

- **pcap reader**: own implementation of the libpcap file format (both byte orders,
  µs and ns timestamps), no libpcap dependency
- **packet decoder**: Ethernet (incl. 802.1Q / QinQ VLAN), BSD loopback, raw IP →
  IPv4 / IPv6 (with extension headers) → TCP / UDP; zero-copy, bounds-checked,
  errors reported via `std::expected`
- **flow table**: bidirectional 5-tuple tracking, client/server detection,
  per-direction packet/byte counters and TCP flags, idle timeout expiry

## Architecture

```
 pcap file ──► PcapReader ──► parse_packet() ──► FlowTable ──► report
               (records)      (L2→L3→L4 view)    (5-tuple → Flow)
                                                        │
                    planned:  L7 classifier ──► policy engine ──► verdict
```

## Build

Requires CMake ≥ 3.24 and a C++23 compiler (GCC 14, Clang 18, Apple Clang 16).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options: `-DL7WALL_SANITIZE=ON` (ASan + UBSan), `-DL7WALL_WERROR=ON`.

## Usage

```bash
sudo tcpdump -i en0 -w capture.pcap -c 1000   # or any pcap from Wireshark samples
./build/l7wall capture.pcap --top 10
```

```
packets: 6 parsed, 1 skipped
  unsupported ethertype    1
flows:   2

PROTO   CLIENT                   SERVER                       PKTS      BYTES  DUR(ms)
TCP     192.168.1.10:51000       142.250.74.14:443               4       2116       60
UDP     192.168.1.10:53000       8.8.8.8:53                      2        174       20
```

## Roadmap

- [x] pcap reader, L2–L4 decoder, flow table
- [ ] TCP state machine (handshake / teardown / RST), per-state timeouts
- [ ] L7 identification: TLS ClientHello SNI, HTTP Host, DNS queries
- [ ] Rule language and policy engine (`block tls sni *.example.com`)
- [ ] Inline mode on Linux via NFQUEUE (accept / drop verdicts on live traffic)
- [ ] Multi-threaded pipeline: RSS-style flow sharding across workers
- [ ] Benchmarks (Google Benchmark), throughput in Mpps
- [ ] pcapng support
