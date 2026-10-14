#include "l7wall/packet.hpp"

#include <algorithm>

#include "l7wall/byte_order.hpp"

namespace l7wall {
namespace {

using Bytes = std::span<const std::uint8_t>;
using Result = std::expected<Packet, ParseError>;

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;

constexpr std::size_t kEthernetHeaderLen = 14;
constexpr std::size_t kVlanTagLen = 4;
constexpr std::size_t kIpv4MinHeaderLen = 20;
constexpr std::size_t kIpv6HeaderLen = 40;
constexpr std::size_t kTcpMinHeaderLen = 20;
constexpr std::size_t kUdpHeaderLen = 8;

constexpr std::uint8_t kIpv6HopByHop = 0;
constexpr std::uint8_t kIpv6Routing = 43;
constexpr std::uint8_t kIpv6Fragment = 44;
constexpr std::uint8_t kIpv6DestOptions = 60;
constexpr int kMaxIpv6ExtHeaders = 8;

Result parse_l4(Bytes data, Packet pkt) noexcept {
    if (pkt.is(IpProtocol::Tcp)) {
        if (data.size() < kTcpMinHeaderLen) {
            return std::unexpected(ParseError::Truncated);
        }
        const auto header_len = static_cast<std::size_t>(data[12] >> 4) * 4;
        if (header_len < kTcpMinHeaderLen) {
            return std::unexpected(ParseError::MalformedL4Header);
        }
        if (header_len > data.size()) {
            return std::unexpected(ParseError::Truncated);
        }
        pkt.src_port = load_be16(&data[0]);
        pkt.dst_port = load_be16(&data[2]);
        pkt.tcp_flags = data[13];
        pkt.payload = data.subspan(header_len);
    } else if (pkt.is(IpProtocol::Udp)) {
        if (data.size() < kUdpHeaderLen) {
            return std::unexpected(ParseError::Truncated);
        }
        const std::size_t udp_len = load_be16(&data[4]);
        if (udp_len < kUdpHeaderLen) {
            return std::unexpected(ParseError::MalformedL4Header);
        }
        pkt.src_port = load_be16(&data[0]);
        pkt.dst_port = load_be16(&data[2]);
        // Payload may be cut short by the capture snaplen.
        pkt.payload = data.subspan(kUdpHeaderLen,
                                   std::min(udp_len, data.size()) - kUdpHeaderLen);
    } else {
        pkt.payload = data;
    }
    return pkt;
}

Result parse_ipv4(Bytes data) noexcept {
    if (data.size() < kIpv4MinHeaderLen) {
        return std::unexpected(ParseError::Truncated);
    }
    if ((data[0] >> 4) != 4) {
        return std::unexpected(ParseError::MalformedIpHeader);
    }
    const auto header_len = static_cast<std::size_t>(data[0] & 0x0F) * 4;
    const std::size_t total_len = load_be16(&data[2]);
    if (header_len < kIpv4MinHeaderLen || total_len < header_len) {
        return std::unexpected(ParseError::MalformedIpHeader);
    }
    if (header_len > data.size()) {
        return std::unexpected(ParseError::Truncated);
    }
    // Drop link-layer padding (Ethernet pads short frames to 60 bytes).
    data = data.first(std::min(total_len, data.size()));

    const std::uint16_t fragment_offset = load_be16(&data[6]) & 0x1FFF;
    if (fragment_offset != 0) {
        return std::unexpected(ParseError::Fragmented);
    }

    Packet pkt;
    pkt.ttl = data[8];
    pkt.protocol = data[9];
    pkt.src_ip = IpAddress::v4(data.subspan<12, 4>());
    pkt.dst_ip = IpAddress::v4(data.subspan<16, 4>());
    return parse_l4(data.subspan(header_len), pkt);
}

Result parse_ipv6(Bytes data) noexcept {
    if (data.size() < kIpv6HeaderLen) {
        return std::unexpected(ParseError::Truncated);
    }
    if ((data[0] >> 4) != 6) {
        return std::unexpected(ParseError::MalformedIpHeader);
    }

    Packet pkt;
    pkt.ttl = data[7];
    pkt.src_ip = IpAddress::v6(data.subspan<8, 16>());
    pkt.dst_ip = IpAddress::v6(data.subspan<24, 16>());

    const std::size_t payload_len = load_be16(&data[4]);
    Bytes rest = data.subspan(kIpv6HeaderLen);
    rest = rest.first(std::min(payload_len, rest.size()));

    std::uint8_t next_header = data[6];
    for (int i = 0; i < kMaxIpv6ExtHeaders; ++i) {
        if (next_header == kIpv6HopByHop || next_header == kIpv6Routing ||
            next_header == kIpv6DestOptions) {
            if (rest.size() < 8) {
                return std::unexpected(ParseError::Truncated);
            }
            const auto ext_len = (static_cast<std::size_t>(rest[1]) + 1) * 8;
            if (ext_len > rest.size()) {
                return std::unexpected(ParseError::Truncated);
            }
            next_header = rest[0];
            rest = rest.subspan(ext_len);
        } else if (next_header == kIpv6Fragment) {
            if (rest.size() < 8) {
                return std::unexpected(ParseError::Truncated);
            }
            if ((load_be16(&rest[2]) >> 3) != 0) {
                return std::unexpected(ParseError::Fragmented);
            }
            next_header = rest[0];
            rest = rest.subspan(8);
        } else {
            break;
        }
    }

    pkt.protocol = next_header;
    return parse_l4(rest, pkt);
}

Result parse_ip(Bytes data) noexcept {
    if (data.empty()) {
        return std::unexpected(ParseError::Truncated);
    }
    switch (data[0] >> 4) {
        case 4:
            return parse_ipv4(data);
        case 6:
            return parse_ipv6(data);
        default:
            return std::unexpected(ParseError::MalformedIpHeader);
    }
}

Result parse_ethernet(Bytes frame) noexcept {
    if (frame.size() < kEthernetHeaderLen) {
        return std::unexpected(ParseError::Truncated);
    }
    std::uint16_t ether_type = load_be16(&frame[12]);
    std::size_t offset = kEthernetHeaderLen;
    while (ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ) {
        if (frame.size() < offset + kVlanTagLen) {
            return std::unexpected(ParseError::Truncated);
        }
        ether_type = load_be16(&frame[offset + 2]);
        offset += kVlanTagLen;
    }

    switch (ether_type) {
        case kEtherTypeIpv4:
            return parse_ipv4(frame.subspan(offset));
        case kEtherTypeIpv6:
            return parse_ipv6(frame.subspan(offset));
        default:
            return std::unexpected(ParseError::UnsupportedEtherType);
    }
}

Result parse_null(Bytes frame) noexcept {
    // 4-byte address family in the *capturing host's* byte order, so accept both.
    if (frame.size() < 4) {
        return std::unexpected(ParseError::Truncated);
    }
    std::uint32_t family = load_le32(frame.data());
    if (family > 0xFFFF) {
        family = load_be32(frame.data());
    }
    constexpr std::uint32_t kAfInet = 2;
    constexpr std::uint32_t kAfInet6Bsd = 24;
    constexpr std::uint32_t kAfInet6FreeBsd = 28;
    constexpr std::uint32_t kAfInet6Darwin = 30;
    switch (family) {
        case kAfInet:
            return parse_ipv4(frame.subspan(4));
        case kAfInet6Bsd:
        case kAfInet6FreeBsd:
        case kAfInet6Darwin:
            return parse_ipv6(frame.subspan(4));
        default:
            return std::unexpected(ParseError::UnsupportedEtherType);
    }
}

}  // namespace

std::expected<Packet, ParseError> parse_packet(std::span<const std::uint8_t> frame,
                                               LinkType link_type) noexcept {
    switch (link_type) {
        case LinkType::Ethernet:
            return parse_ethernet(frame);
        case LinkType::Raw:
            return parse_ip(frame);
        case LinkType::Null:
            return parse_null(frame);
    }
    return std::unexpected(ParseError::UnsupportedLinkType);
}

std::string_view to_string(ParseError err) noexcept {
    switch (err) {
        case ParseError::Truncated:
            return "truncated";
        case ParseError::UnsupportedLinkType:
            return "unsupported link type";
        case ParseError::UnsupportedEtherType:
            return "unsupported ethertype";
        case ParseError::MalformedIpHeader:
            return "malformed IP header";
        case ParseError::MalformedL4Header:
            return "malformed L4 header";
        case ParseError::Fragmented:
            return "IP fragment";
    }
    return "unknown";
}

std::string_view protocol_name(std::uint8_t protocol) noexcept {
    switch (static_cast<IpProtocol>(protocol)) {
        case IpProtocol::Icmp:
            return "ICMP";
        case IpProtocol::Tcp:
            return "TCP";
        case IpProtocol::Udp:
            return "UDP";
        case IpProtocol::IcmpV6:
            return "ICMPv6";
    }
    return "OTHER";
}

}  // namespace l7wall
