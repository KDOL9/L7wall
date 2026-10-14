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
    EXPECT_EQ(flow.tcp_state, TcpState::Established);
}

TEST(FlowTable, TracksGracefulClose) {
    FlowTable table;
    table.update(make_tcp(kClient, 51000, kServer, 443, tcp_flags::Ack), 1s, 54);
    const Flow& closing =
        table.update(make_tcp(kClient, 51000, kServer, 443, tcp_flags::Fin | tcp_flags::Ack), 2s, 54);
    EXPECT_EQ(closing.tcp_state, TcpState::Closing);

    const Flow& closed =
        table.update(make_tcp(kServer, 443, kClient, 51000, tcp_flags::Fin | tcp_flags::Ack), 3s, 54);
    EXPECT_EQ(closed.tcp_state, TcpState::Closed);
}

TEST(FlowTable, TracksReset) {
    FlowTable table;
    table.update(make_tcp(kClient, 51000, kServer, 443, tcp_flags::Syn), 1s, 60);
    const Flow& flow = table.update(make_tcp(kServer, 443, kClient, 51000, tcp_flags::Rst), 2s, 54);

    EXPECT_EQ(flow.tcp_state, TcpState::Reset);
}

TEST(FlowTable, UdpFlowsHaveNoTcpState) {
    Packet pkt = make_tcp(kClient, 5353, kServer, 53, 0);
    pkt.protocol = static_cast<std::uint8_t>(IpProtocol::Udp);
    FlowTable table;

    EXPECT_EQ(table.update(pkt, 1s, 60).tcp_state, TcpState::New);
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
    FlowTable table({.tcp_established = 30s});
    table.update(make_tcp(kClient, 1000, kServer, 80, 0), 0s, 60);
    table.update(make_tcp(kClient, 2000, kServer, 80, 0), 20s, 60);

    const auto expired = table.expire(35s);

    ASSERT_EQ(expired.size(), 1u);
    EXPECT_EQ(expired[0].client.port, 1000);
    EXPECT_EQ(table.size(), 1u);
    EXPECT_EQ(table.find(expired[0].key), nullptr);
}

TEST(FlowTable, AppliesTimeoutPerTcpState) {
    FlowTable table({.tcp_established = 3600s, .tcp_closed = 10s});
    table.update(make_tcp(kClient, 1000, kServer, 80, tcp_flags::Ack), 0s, 60);
    table.update(make_tcp(kClient, 2000, kServer, 80, tcp_flags::Ack), 0s, 60);
    table.update(make_tcp(kServer, 80, kClient, 2000, tcp_flags::Rst), 1s, 54);

    const auto expired = table.expire(20s);

    ASSERT_EQ(expired.size(), 1u);
    EXPECT_EQ(expired[0].client.port, 2000);
    EXPECT_EQ(expired[0].tcp_state, TcpState::Reset);
}

TEST(FlowTable, UsesProtocolTimeoutsForUdp) {
    Packet pkt = make_tcp(kClient, 5353, kServer, 53, 0);
    pkt.protocol = static_cast<std::uint8_t>(IpProtocol::Udp);
    FlowTable table({.tcp_established = 3600s, .udp = 30s});
    table.update(pkt, 0s, 60);

    EXPECT_TRUE(table.expire(29s).empty());
    EXPECT_EQ(table.expire(30s).size(), 1u);
}

}  // namespace
}  // namespace l7wall
