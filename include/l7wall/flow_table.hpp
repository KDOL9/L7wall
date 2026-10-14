#pragma once

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "l7wall/ip_address.hpp"
#include "l7wall/packet.hpp"
#include "l7wall/tcp_state.hpp"

namespace l7wall {

// Direction-independent 5-tuple: both directions of a connection map to the same key.
struct FlowKey {
    IpAddress ip_lo;
    IpAddress ip_hi;
    std::uint16_t port_lo = 0;
    std::uint16_t port_hi = 0;
    std::uint8_t protocol = 0;

    [[nodiscard]] static FlowKey from_packet(const Packet& pkt) noexcept;

    friend auto operator<=>(const FlowKey&, const FlowKey&) = default;
};

struct FlowKeyHash {
    [[nodiscard]] std::size_t operator()(const FlowKey& key) const noexcept;
};

struct Endpoint {
    IpAddress ip;
    std::uint16_t port = 0;

    friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

struct DirectionStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint8_t tcp_flags = 0;  // union of all TCP flags seen in this direction
};

struct Flow {
    FlowKey key;
    Endpoint client;  // connection initiator
    Endpoint server;
    std::uint8_t protocol = 0;
    TcpState tcp_state = TcpState::New;
    Timestamp first_seen{};
    Timestamp last_seen{};
    DirectionStats to_server;
    DirectionStats to_client;

    [[nodiscard]] std::uint64_t total_packets() const noexcept {
        return to_server.packets + to_client.packets;
    }
    [[nodiscard]] std::uint64_t total_bytes() const noexcept {
        return to_server.bytes + to_client.bytes;
    }
};

struct TimeoutPolicy {
    std::chrono::seconds tcp_handshake{30};
    std::chrono::seconds tcp_established{3600};
    std::chrono::seconds tcp_closing{60};
    std::chrono::seconds tcp_closed{10};
    std::chrono::seconds udp{60};
    std::chrono::seconds other{30};

    [[nodiscard]] std::chrono::seconds timeout_for(const Flow& flow) const noexcept;
};

class FlowTable {
public:
    explicit FlowTable(TimeoutPolicy policy = {});

    // Accounts the packet to its flow, creating the flow on first sight.
    Flow& update(const Packet& pkt, Timestamp ts, std::size_t wire_bytes);

    std::vector<Flow> expire(Timestamp now);

    [[nodiscard]] const Flow* find(const FlowKey& key) const;
    [[nodiscard]] std::size_t size() const noexcept { return flows_.size(); }

    template <typename F>
    void for_each(F&& fn) const {
        for (const auto& [key, flow] : flows_) {
            fn(flow);
        }
    }

private:
    TimeoutPolicy policy_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
};

}  // namespace l7wall
