#pragma once

#include <cstdint>
#include <string_view>

namespace l7wall {

enum class TcpState : std::uint8_t {
    New,
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
    Reset,
};

struct TcpEvent {
    std::uint8_t flags = 0;
    bool from_client = false;
    bool fin_seen_both_ways = false;
};

[[nodiscard]] TcpState next_tcp_state(TcpState current, const TcpEvent& event) noexcept;

[[nodiscard]] std::string_view to_string(TcpState state) noexcept;

}  // namespace l7wall
