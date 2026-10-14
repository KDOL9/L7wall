#include "l7wall/ip_address.hpp"

#include <algorithm>
#include <format>

#include "l7wall/byte_order.hpp"

namespace l7wall {

IpAddress IpAddress::v4(std::span<const std::uint8_t, 4> bytes) noexcept {
    IpAddress addr;
    addr.family_ = Family::V4;
    std::ranges::copy(bytes, addr.bytes_.begin());
    return addr;
}

IpAddress IpAddress::v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
    const std::array<std::uint8_t, 4> bytes{a, b, c, d};
    return v4(bytes);
}

IpAddress IpAddress::v6(std::span<const std::uint8_t, 16> bytes) noexcept {
    IpAddress addr;
    addr.family_ = Family::V6;
    std::ranges::copy(bytes, addr.bytes_.begin());
    return addr;
}

std::span<const std::uint8_t> IpAddress::bytes() const noexcept {
    return std::span{bytes_}.first(is_v4() ? 4 : 16);
}

std::string IpAddress::to_string() const {
    if (is_v4()) {
        return std::format("{}.{}.{}.{}", bytes_[0], bytes_[1], bytes_[2], bytes_[3]);
    }

    std::array<std::uint16_t, 8> groups{};
    for (std::size_t i = 0; i < groups.size(); ++i) {
        groups[i] = load_be16(&bytes_[i * 2]);
    }

    // RFC 5952: compress the longest run (>= 2 groups) of zero groups with "::".
    std::size_t best_start = groups.size();
    std::size_t best_len = 0;
    for (std::size_t i = 0; i < groups.size();) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < groups.size() && groups[j] == 0) {
            ++j;
        }
        if (j - i > best_len) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    if (best_len < 2) {
        best_start = groups.size();
    }

    std::string out;
    for (std::size_t i = 0; i < groups.size();) {
        if (i == best_start) {
            out += "::";
            i += best_len;
            continue;
        }
        if (!out.empty() && out.back() != ':') {
            out += ':';
        }
        out += std::format("{:x}", groups[i]);
        ++i;
    }
    return out;
}

std::size_t IpAddress::hash() const noexcept {
    // FNV-1a over the address bytes and family.
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (const std::uint8_t b : bytes_) {
        h = (h ^ b) * 0x100000001b3ULL;
    }
    h = (h ^ static_cast<std::uint8_t>(family_)) * 0x100000001b3ULL;
    return static_cast<std::size_t>(h);
}

}  // namespace l7wall
