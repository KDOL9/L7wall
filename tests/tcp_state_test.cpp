#include "l7wall/tcp_state.hpp"

#include <gtest/gtest.h>

#include "l7wall/packet.hpp"

namespace l7wall {
namespace {

using namespace tcp_flags;

TcpEvent from_client(std::uint8_t flags, bool fin_both = false) {
    return {.flags = flags, .from_client = true, .fin_seen_both_ways = fin_both};
}

TcpEvent from_server(std::uint8_t flags, bool fin_both = false) {
    return {.flags = flags, .from_client = false, .fin_seen_both_ways = fin_both};
}

TEST(TcpState, ThreeWayHandshake) {
    TcpState s = TcpState::New;

    s = next_tcp_state(s, from_client(Syn));
    EXPECT_EQ(s, TcpState::SynSent);

    s = next_tcp_state(s, from_server(Syn | Ack));
    EXPECT_EQ(s, TcpState::SynReceived);

    s = next_tcp_state(s, from_client(Ack));
    EXPECT_EQ(s, TcpState::Established);
}

TEST(TcpState, RetransmittedSynKeepsSynSent) {
    EXPECT_EQ(next_tcp_state(TcpState::SynSent, from_client(Syn)), TcpState::SynSent);
}

TEST(TcpState, SynAckFromClientDoesNotAdvance) {
    EXPECT_EQ(next_tcp_state(TcpState::SynSent, from_client(Syn | Ack)), TcpState::SynSent);
}

TEST(TcpState, FirstPacketSynAckStartsInSynReceived) {
    EXPECT_EQ(next_tcp_state(TcpState::New, from_server(Syn | Ack)), TcpState::SynReceived);
}

TEST(TcpState, MidstreamPickupIsEstablished) {
    EXPECT_EQ(next_tcp_state(TcpState::New, from_client(Ack | Psh)), TcpState::Established);
}

TEST(TcpState, GracefulClose) {
    TcpState s = TcpState::Established;

    s = next_tcp_state(s, from_client(Fin | Ack));
    EXPECT_EQ(s, TcpState::Closing);

    s = next_tcp_state(s, from_server(Ack));
    EXPECT_EQ(s, TcpState::Closing);

    s = next_tcp_state(s, from_server(Fin | Ack, true));
    EXPECT_EQ(s, TcpState::Closed);

    s = next_tcp_state(s, from_client(Ack, true));
    EXPECT_EQ(s, TcpState::Closed);
}

TEST(TcpState, RstResetsFromAnyActiveState) {
    for (const TcpState s : {TcpState::New, TcpState::SynSent, TcpState::SynReceived,
                             TcpState::Established, TcpState::Closing}) {
        EXPECT_EQ(next_tcp_state(s, from_server(Rst)), TcpState::Reset) << to_string(s);
    }
}

TEST(TcpState, TerminalStatesAreSticky) {
    EXPECT_EQ(next_tcp_state(TcpState::Reset, from_client(Syn)), TcpState::Reset);
    EXPECT_EQ(next_tcp_state(TcpState::Closed, from_client(Rst)), TcpState::Closed);
}

TEST(TcpState, FinDuringHandshakeIsIgnored) {
    EXPECT_EQ(next_tcp_state(TcpState::SynSent, from_client(Fin)), TcpState::SynSent);
}

}  // namespace
}  // namespace l7wall
