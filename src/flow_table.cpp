#include "l7wall/flow_table.hpp"

#include <algorithm>
#include <tuple>

namespace l7wall {
namespace {

void hash_combine(std::size_t& seed, std::size_t value) noexcept {
    seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

}  // namespace

FlowKey FlowKey::from_packet(const Packet& pkt) noexcept {
    FlowKey key;
    key.protocol = pkt.protocol;
    if (std::tie(pkt.src_ip, pkt.src_port) <= std::tie(pkt.dst_ip, pkt.dst_port)) {
        key.ip_lo = pkt.src_ip;
        key.port_lo = pkt.src_port;
        key.ip_hi = pkt.dst_ip;
        key.port_hi = pkt.dst_port;
    } else {
        key.ip_lo = pkt.dst_ip;
        key.port_lo = pkt.dst_port;
        key.ip_hi = pkt.src_ip;
        key.port_hi = pkt.src_port;
    }
    return key;
}

std::size_t FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    std::size_t seed = key.ip_lo.hash();
    hash_combine(seed, key.ip_hi.hash());
    hash_combine(seed, (std::size_t{key.port_lo} << 16) | key.port_hi);
    hash_combine(seed, key.protocol);
    return seed;
}

std::chrono::seconds TimeoutPolicy::timeout_for(const Flow& flow) const noexcept {
    if (flow.protocol == static_cast<std::uint8_t>(IpProtocol::Udp)) {
        return udp;
    }
    if (flow.protocol != static_cast<std::uint8_t>(IpProtocol::Tcp)) {
        return other;
    }
    switch (flow.tcp_state) {
        case TcpState::New:
        case TcpState::SynSent:
        case TcpState::SynReceived:
            return tcp_handshake;
        case TcpState::Established:
            return tcp_established;
        case TcpState::Closing:
            return tcp_closing;
        case TcpState::Closed:
        case TcpState::Reset:
            return tcp_closed;
    }
    return other;
}

FlowTable::FlowTable(TimeoutPolicy policy) : policy_(policy) {}

Flow& FlowTable::update(const Packet& pkt, Timestamp ts, std::size_t wire_bytes) {
    const FlowKey key = FlowKey::from_packet(pkt);
    auto [it, inserted] = flows_.try_emplace(key);
    Flow& flow = it->second;

    if (inserted) {
        flow.key = key;
        flow.protocol = pkt.protocol;
        flow.first_seen = ts;
        flow.client = {pkt.src_ip, pkt.src_port};
        flow.server = {pkt.dst_ip, pkt.dst_port};
        // Capture started mid-handshake: a SYN-ACK comes from the server.
        constexpr auto kSynAck = tcp_flags::Syn | tcp_flags::Ack;
        if (pkt.is(IpProtocol::Tcp) && (pkt.tcp_flags & kSynAck) == kSynAck) {
            std::swap(flow.client, flow.server);
        }
    }

    flow.last_seen = std::max(flow.last_seen, ts);
    const bool from_client = Endpoint{pkt.src_ip, pkt.src_port} == flow.client;
    DirectionStats& dir = from_client ? flow.to_server : flow.to_client;
    ++dir.packets;
    dir.bytes += wire_bytes;
    dir.tcp_flags |= pkt.tcp_flags;

    if (pkt.is(IpProtocol::Tcp)) {
        const bool fin_both = (flow.to_server.tcp_flags & tcp_flags::Fin) != 0 &&
                              (flow.to_client.tcp_flags & tcp_flags::Fin) != 0;
        flow.tcp_state = next_tcp_state(flow.tcp_state, {.flags = pkt.tcp_flags,
                                                         .from_client = from_client,
                                                         .fin_seen_both_ways = fin_both});
    }
    return flow;
}

std::vector<Flow> FlowTable::expire(Timestamp now) {
    std::vector<Flow> expired;
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (now - it->second.last_seen >= policy_.timeout_for(it->second)) {
            expired.push_back(std::move(it->second));
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

const Flow* FlowTable::find(const FlowKey& key) const {
    const auto it = flows_.find(key);
    return it == flows_.end() ? nullptr : &it->second;
}

}  // namespace l7wall
