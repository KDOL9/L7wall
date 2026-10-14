#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "l7wall/ip_address.hpp"

namespace l7wall {

using Timestamp = std::chrono::nanoseconds;  // since Unix epoch

// Values follow the tcpdump LINKTYPE_* registry.
enum class LinkType : std::uint32_t {
    Null = 0,  // BSD loopback (e.g. macOS lo0)
    Ethernet = 1,
    Raw = 101,  // raw IPv4/IPv6, no link-layer header
};

enum class IpProtocol : std::uint8_t {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    IcmpV6 = 58,
};

namespace tcp_flags {
inline constexpr std::uint8_t Fin = 0x01;
inline constexpr std::uint8_t Syn = 0x02;
inline constexpr std::uint8_t Rst = 0x04;
inline constexpr std::uint8_t Psh = 0x08;
inline constexpr std::uint8_t Ack = 0x10;
inline constexpr std::uint8_t Urg = 0x20;
}  // namespace tcp_flags

// Decoded L3/L4 view of a frame. `payload` points into the original frame buffer,
// so a Packet must not outlive the bytes it was parsed from.
struct Packet {
    IpAddress src_ip;
    IpAddress dst_ip;
    std::uint8_t protocol = 0;
    std::uint8_t ttl = 0;  // TTL for IPv4, hop limit for IPv6
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint8_t tcp_flags = 0;
    std::span<const std::uint8_t> payload;  // L4 payload

    [[nodiscard]] bool is(IpProtocol p) const noexcept {
        return protocol == static_cast<std::uint8_t>(p);
    }
};

enum class ParseError {
    Truncated,
    UnsupportedLinkType,
    UnsupportedEtherType,
    MalformedIpHeader,
    MalformedL4Header,
    Fragmented,  // non-first IP fragment: no L4 header to read
};

[[nodiscard]] std::string_view to_string(ParseError err) noexcept;
[[nodiscard]] std::string_view protocol_name(std::uint8_t protocol) noexcept;

[[nodiscard]] std::expected<Packet, ParseError> parse_packet(std::span<const std::uint8_t> frame,
                                                             LinkType link_type) noexcept;

}  // namespace l7wall
