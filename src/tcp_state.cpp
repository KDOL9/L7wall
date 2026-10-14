#include "l7wall/tcp_state.hpp"

#include "l7wall/packet.hpp"

namespace l7wall {
namespace {

bool has(std::uint8_t flags, std::uint8_t mask) noexcept {
    return (flags & mask) == mask;
}

TcpState advance_handshake(TcpState current, const TcpEvent& event) noexcept {
    const bool syn = has(event.flags, tcp_flags::Syn);
    const bool ack = has(event.flags, tcp_flags::Ack);

    switch (current) {
        case TcpState::New:
            if (syn) {
                return ack ? TcpState::SynReceived : TcpState::SynSent;
            }
            return TcpState::Established;
        case TcpState::SynSent:
            if (syn && ack && !event.from_client) {
                return TcpState::SynReceived;
            }
            return current;
        case TcpState::SynReceived:
            if (ack && !syn && event.from_client) {
                return TcpState::Established;
            }
            return current;
        default:
            return current;
    }
}

}  // namespace

TcpState next_tcp_state(TcpState current, const TcpEvent& event) noexcept {
    if (current == TcpState::Closed || current == TcpState::Reset) {
        return current;
    }
    if (has(event.flags, tcp_flags::Rst)) {
        return TcpState::Reset;
    }

    const TcpState state = advance_handshake(current, event);

    const bool can_close = state == TcpState::Established || state == TcpState::Closing;
    if (can_close && has(event.flags, tcp_flags::Fin)) {
        return event.fin_seen_both_ways ? TcpState::Closed : TcpState::Closing;
    }
    return state;
}

std::string_view to_string(TcpState state) noexcept {
    switch (state) {
        case TcpState::New:
            return "NEW";
        case TcpState::SynSent:
            return "SYN_SENT";
        case TcpState::SynReceived:
            return "SYN_RECV";
        case TcpState::Established:
            return "ESTABLISHED";
        case TcpState::Closing:
            return "CLOSING";
        case TcpState::Closed:
            return "CLOSED";
        case TcpState::Reset:
            return "RESET";
    }
    return "UNKNOWN";
}

}  // namespace l7wall
