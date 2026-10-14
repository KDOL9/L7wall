#include "l7wall/flow_table.hpp"

#include <gtest/gtest.h>

namespace l7wall {
namespace {

using namespace std::chrono_literals;

const IpAddress kClient = IpAddress::v4(10, 0, 0, 1);
const IpAddress kServer = IpAddress::v4(93, 184, 216, 34);

Packet make_tcp(const IpAddress& src, std::uint16_t sport, const IpAddress& dst,
                std::uint16_t dport, std::uint8_t flags) {
    Packet pkt;
    pkt.src_ip = src;
    pkt.dst_ip = dst;
    pkt.src_port = sport;
    pkt.dst_port = dport;
    pkt.protocol = static_cast<std::uint8_t>(IpProtocol::Tcp);
    pkt.tcp_flags = flags;
    return pkt;
}

TEST(FlowKey, IsSameForBothDirections) {
    const auto forward = make_tcp(kClient, 51000, kServer, 443, 0);
    const auto reverse = make_tcp(kServer, 443, kClient, 51000, 0);

    EXPECT_EQ(FlowKey::from_packet(forward), FlowKey::from_packet(reverse));
    EXPECT_EQ(FlowKeyHash{}(FlowKey::from_packet(forward)),
              FlowKeyHash{}(FlowKey::from_packet(reverse)));
}

TEST(FlowKey, DiffersByProtocolAndPort) {
    auto a = make_tcp(kClient, 51000, kServer, 443, 0);
    auto b = a;
    b.protocol = static_cast<std::uint8_t>(IpProtocol::Udp);
    auto c = a;
    c.src_port = 51001;

    EXPECT_NE(FlowKey::from_packet(a), FlowKey::from_packet(b));
    EXPECT_NE(FlowKey::from_packet(a), FlowKey::from_packet(c));
}

TEST(FlowTable, TracksHandshakeAsOneFlow) {
    FlowTable table;
    table.update(make_tcp(kClient, 51000, kServer, 443, tcp_flags::Syn), 1s, 60);
    table.update(make_tcp(kServer, 443, kClient, 51000, tcp_flags::Syn | tcp_flags::Ack), 2s, 60);
    const Flow& flow = table.update(make_tcp(kClient, 51000, kServer, 443, tcp_flags::Ack), 3s, 54);

    EXPECT_EQ(table.size(), 1u);
    EXPECT_EQ(flow.client, (Endpoint{kClient, 51000}));
    EXPECT_EQ(flow.server, (Endpoint{kServer, 443}));
    EXPECT_EQ(flow.to_server.packets, 2u);
    EXPECT_EQ(flow.to_server.bytes, 114u);
    EXPECT_EQ(flow.to_client.packets, 1u);
    EXPECT_EQ(flow.to_server.tcp_flags, tcp_flags::Syn | tcp_flags::Ack);
    EXPECT_EQ(flow.to_client.tcp_flags, tcp_flags::Syn | tcp_flags::Ack);
    EXPECT_EQ(flow.first_seen, 1s);
    EXPECT_EQ(flow.last_seen, 3s);
}

TEST(FlowTable, SynAckFirstMakesSenderTheServer) {
    FlowTable table;
    const Flow& flow = table.update(
        make_tcp(kServer, 443, kClient, 51000, tcp_flags::Syn | tcp_flags::Ack), 1s, 60);

    EXPECT_EQ(flow.client, (Endpoint{kClient, 51000}));
    EXPECT_EQ(flow.to_client.packets, 1u);
    EXPECT_EQ(flow.to_server.packets, 0u);
}

TEST(FlowTable, ExpiresIdleFlows) {
    FlowTable table(30s);
    table.update(make_tcp(kClient, 1000, kServer, 80, 0), 0s, 60);
    table.update(make_tcp(kClient, 2000, kServer, 80, 0), 20s, 60);

    const auto expired = table.expire(35s);

    ASSERT_EQ(expired.size(), 1u);
    EXPECT_EQ(expired[0].client.port, 1000);
    EXPECT_EQ(table.size(), 1u);
    EXPECT_EQ(table.find(expired[0].key), nullptr);
}

}  // namespace
}  // namespace l7wall
