#include "l7wall/packet.hpp"

#include <gtest/gtest.h>

#include <algorithm>

#include "frame_builder.hpp"

namespace l7wall {
namespace {

using namespace l7wall::test;

constexpr std::array<std::uint8_t, 4> kClient{10, 0, 0, 1};
constexpr std::array<std::uint8_t, 4> kServer{93, 184, 216, 34};
constexpr std::array<std::uint8_t, 16> kClient6{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
constexpr std::array<std::uint8_t, 16> kServer6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                                0,    0,    0,    0,    0, 0, 0, 2};
constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;

const Bytes kHello{'h', 'e', 'l', 'l', 'o'};

TEST(ParsePacket, Ipv4Tcp) {
    const Bytes frame =
        ethernet(0x0800, ipv4(kClient, kServer, kTcp, tcp(51000, 443, tcp_flags::Syn, kHello)));

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_TRUE(pkt) << to_string(pkt.error());
    EXPECT_EQ(pkt->src_ip, IpAddress::v4(kClient));
    EXPECT_EQ(pkt->dst_ip, IpAddress::v4(kServer));
    EXPECT_TRUE(pkt->is(IpProtocol::Tcp));
    EXPECT_EQ(pkt->src_port, 51000);
    EXPECT_EQ(pkt->dst_port, 443);
    EXPECT_EQ(pkt->tcp_flags, tcp_flags::Syn);
    EXPECT_EQ(pkt->ttl, 64);
    EXPECT_TRUE(std::ranges::equal(pkt->payload, kHello));
}

TEST(ParsePacket, Ipv4Udp) {
    const Bytes frame = ethernet(0x0800, ipv4(kClient, kServer, kUdp, udp(5353, 53, kHello)));

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_TRUE(pkt);
    EXPECT_TRUE(pkt->is(IpProtocol::Udp));
    EXPECT_EQ(pkt->src_port, 5353);
    EXPECT_EQ(pkt->dst_port, 53);
    EXPECT_TRUE(std::ranges::equal(pkt->payload, kHello));
}

TEST(ParsePacket, IgnoresEthernetPadding) {
    Bytes frame = ethernet(0x0800, ipv4(kClient, kServer, kTcp, tcp(1, 2, tcp_flags::Ack)));
    frame.resize(60, 0);  // minimum Ethernet frame size

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_TRUE(pkt);
    EXPECT_TRUE(pkt->payload.empty());
}

TEST(ParsePacket, SkipsVlanTags) {
    const Bytes ip = ipv4(kClient, kServer, kUdp, udp(1000, 2000));
    Bytes vlan_payload;
    push_be16(vlan_payload, 100);     // TCI
    push_be16(vlan_payload, 0x0800);  // inner ethertype
    append(vlan_payload, ip);

    const auto pkt = parse_packet(ethernet(0x8100, vlan_payload), LinkType::Ethernet);

    ASSERT_TRUE(pkt);
    EXPECT_EQ(pkt->dst_port, 2000);
}

TEST(ParsePacket, Ipv6Udp) {
    const Bytes frame = ethernet(0x86DD, ipv6(kClient6, kServer6, kUdp, udp(40000, 53, kHello)));

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_TRUE(pkt);
    EXPECT_EQ(pkt->src_ip, IpAddress::v6(kClient6));
    EXPECT_EQ(pkt->dst_ip.to_string(), "2001:db8::2");
    EXPECT_EQ(pkt->dst_port, 53);
    EXPECT_EQ(pkt->ttl, 255);
    EXPECT_TRUE(std::ranges::equal(pkt->payload, kHello));
}

TEST(ParsePacket, Ipv6SkipsExtensionHeaders) {
    Bytes ext{kTcp, 0, 0, 0, 0, 0, 0, 0};  // hop-by-hop, 8 bytes, next = TCP
    append(ext, tcp(1234, 80, tcp_flags::Syn));
    const Bytes frame = ethernet(0x86DD, ipv6(kClient6, kServer6, 0, ext));

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_TRUE(pkt);
    EXPECT_TRUE(pkt->is(IpProtocol::Tcp));
    EXPECT_EQ(pkt->dst_port, 80);
}

TEST(ParsePacket, RawIpLinkType) {
    const Bytes frame = ipv4(kClient, kServer, kUdp, udp(1, 2));

    const auto pkt = parse_packet(frame, LinkType::Raw);

    ASSERT_TRUE(pkt);
    EXPECT_EQ(pkt->dst_port, 2);
}

TEST(ParsePacket, BsdLoopbackLinkType) {
    Bytes frame;
    push_le32(frame, 2);  // AF_INET in little-endian host order
    append(frame, ipv4(kClient, kServer, kUdp, udp(1, 2)));

    const auto pkt = parse_packet(frame, LinkType::Null);

    ASSERT_TRUE(pkt);
    EXPECT_EQ(pkt->dst_port, 2);
}

TEST(ParsePacket, RejectsNonFirstFragment) {
    const Bytes frame =
        ethernet(0x0800, ipv4(kClient, kServer, kUdp, udp(1, 2), /*flags_and_offset=*/0x0010));

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_FALSE(pkt);
    EXPECT_EQ(pkt.error(), ParseError::Fragmented);
}

TEST(ParsePacket, RejectsUnsupportedEtherType) {
    const Bytes frame = ethernet(0x0806, Bytes(28, 0));  // ARP

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_FALSE(pkt);
    EXPECT_EQ(pkt.error(), ParseError::UnsupportedEtherType);
}

TEST(ParsePacket, RejectsTruncatedFrames) {
    const Bytes full = ethernet(0x0800, ipv4(kClient, kServer, kTcp, tcp(1, 2, 0)));
    // Every strict prefix that cuts into a header must fail cleanly, never read out of bounds.
    for (std::size_t len = 0; len < full.size(); ++len) {
        const auto pkt = parse_packet(std::span{full}.first(len), LinkType::Ethernet);
        ASSERT_FALSE(pkt) << "len=" << len;
        EXPECT_EQ(pkt.error(), ParseError::Truncated) << "len=" << len;
    }
}

TEST(ParsePacket, RejectsBadTcpDataOffset) {
    Bytes segment = tcp(1, 2, 0);
    segment[12] = 2 << 4;  // 8 bytes, below the minimum of 20
    const Bytes frame = ethernet(0x0800, ipv4(kClient, kServer, kTcp, segment));

    const auto pkt = parse_packet(frame, LinkType::Ethernet);

    ASSERT_FALSE(pkt);
    EXPECT_EQ(pkt.error(), ParseError::MalformedL4Header);
}

}  // namespace
}  // namespace l7wall
