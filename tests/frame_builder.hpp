#pragma once

// Helpers for building raw frames and pcap files in tests.

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace l7wall::test {

using Bytes = std::vector<std::uint8_t>;

inline void push_be16(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

inline void push_be32(Bytes& out, std::uint32_t v) {
    push_be16(out, static_cast<std::uint16_t>(v >> 16));
    push_be16(out, static_cast<std::uint16_t>(v));
}

inline void push_le16(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
}

inline void push_le32(Bytes& out, std::uint32_t v) {
    push_le16(out, static_cast<std::uint16_t>(v));
    push_le16(out, static_cast<std::uint16_t>(v >> 16));
}

inline void append(Bytes& out, std::span<const std::uint8_t> data) {
    out.insert(out.end(), data.begin(), data.end());
}

inline Bytes tcp(std::uint16_t sport, std::uint16_t dport, std::uint8_t flags,
                 std::span<const std::uint8_t> payload = {}) {
    Bytes out;
    push_be16(out, sport);
    push_be16(out, dport);
    push_be32(out, 1000);  // seq
    push_be32(out, 0);     // ack
    out.push_back(5 << 4);  // data offset: 5 words
    out.push_back(flags);
    push_be16(out, 65535);  // window
    push_be16(out, 0);      // checksum
    push_be16(out, 0);      // urgent pointer
    append(out, payload);
    return out;
}

inline Bytes udp(std::uint16_t sport, std::uint16_t dport,
                 std::span<const std::uint8_t> payload = {}) {
    Bytes out;
    push_be16(out, sport);
    push_be16(out, dport);
    push_be16(out, static_cast<std::uint16_t>(8 + payload.size()));
    push_be16(out, 0);
    append(out, payload);
    return out;
}

inline Bytes ipv4(std::array<std::uint8_t, 4> src, std::array<std::uint8_t, 4> dst,
                  std::uint8_t protocol, std::span<const std::uint8_t> l4,
                  std::uint16_t flags_and_offset = 0) {
    Bytes out;
    out.push_back(0x45);  // version 4, IHL 5
    out.push_back(0);
    push_be16(out, static_cast<std::uint16_t>(20 + l4.size()));
    push_be16(out, 0x1234);  // id
    push_be16(out, flags_and_offset);
    out.push_back(64);  // TTL
    out.push_back(protocol);
    push_be16(out, 0);  // checksum
    append(out, src);
    append(out, dst);
    append(out, l4);
    return out;
}

inline Bytes ipv6(std::array<std::uint8_t, 16> src, std::array<std::uint8_t, 16> dst,
                  std::uint8_t next_header, std::span<const std::uint8_t> payload) {
    Bytes out;
    push_be32(out, 0x60000000);  // version 6
    push_be16(out, static_cast<std::uint16_t>(payload.size()));
    out.push_back(next_header);
    out.push_back(255);  // hop limit
    append(out, src);
    append(out, dst);
    append(out, payload);
    return out;
}

inline Bytes ethernet(std::uint16_t ether_type, std::span<const std::uint8_t> payload) {
    Bytes out(12, 0xAA);  // dst + src MAC
    push_be16(out, ether_type);
    append(out, payload);
    return out;
}

struct PcapOptions {
    bool big_endian = false;
    bool nanosecond = false;
    std::uint32_t link_type = 1;
};

struct PcapFrame {
    std::uint32_t ts_sec = 0;
    std::uint32_t ts_frac = 0;
    Bytes data;
};

inline Bytes pcap_file(std::span<const PcapFrame> frames, PcapOptions opts = {}) {
    auto put32 = [&](Bytes& out, std::uint32_t v) {
        opts.big_endian ? push_be32(out, v) : push_le32(out, v);
    };
    auto put16 = [&](Bytes& out, std::uint16_t v) {
        opts.big_endian ? push_be16(out, v) : push_le16(out, v);
    };

    Bytes out;
    put32(out, opts.nanosecond ? 0xA1B23C4D : 0xA1B2C3D4);
    put16(out, 2);
    put16(out, 4);
    put32(out, 0);  // thiszone
    put32(out, 0);  // sigfigs
    put32(out, 65535);
    put32(out, opts.link_type);
    for (const PcapFrame& frame : frames) {
        put32(out, frame.ts_sec);
        put32(out, frame.ts_frac);
        put32(out, static_cast<std::uint32_t>(frame.data.size()));
        put32(out, static_cast<std::uint32_t>(frame.data.size()));
        append(out, frame.data);
    }
    return out;
}

}  // namespace l7wall::test
