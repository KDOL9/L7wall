#pragma once

#include <cstdint>

// Unaligned loads from raw packet bytes. Callers must check bounds beforehand.
namespace l7wall {

[[nodiscard]] constexpr std::uint16_t load_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

[[nodiscard]] constexpr std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
           (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}

[[nodiscard]] constexpr std::uint16_t load_le16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[1] << 8) | p[0]);
}

[[nodiscard]] constexpr std::uint32_t load_le32(const std::uint8_t* p) noexcept {
    return (std::uint32_t{p[3]} << 24) | (std::uint32_t{p[2]} << 16) |
           (std::uint32_t{p[1]} << 8) | std::uint32_t{p[0]};
}

}  // namespace l7wall
