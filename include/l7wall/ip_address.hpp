#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace l7wall {

// IPv4 or IPv6 address stored in a fixed 16-byte buffer (IPv4 uses the first 4 bytes).
class IpAddress {
public:
    enum class Family : std::uint8_t { V4, V6 };

    IpAddress() = default;

    [[nodiscard]] static IpAddress v4(std::span<const std::uint8_t, 4> bytes) noexcept;
    [[nodiscard]] static IpAddress v4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                                      std::uint8_t d) noexcept;
    [[nodiscard]] static IpAddress v6(std::span<const std::uint8_t, 16> bytes) noexcept;

    [[nodiscard]] Family family() const noexcept { return family_; }
    [[nodiscard]] bool is_v4() const noexcept { return family_ == Family::V4; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept;

    // Dotted quad for IPv4, RFC 5952 canonical form for IPv6.
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::size_t hash() const noexcept;

    friend auto operator<=>(const IpAddress&, const IpAddress&) = default;

private:
    Family family_ = Family::V4;
    std::array<std::uint8_t, 16> bytes_{};
};

}  // namespace l7wall
