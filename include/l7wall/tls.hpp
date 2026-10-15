#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace l7wall::tls {

enum class SniError {
    NotTls,
    NotClientHello,
    Incomplete,
    Malformed,
    NoSni,
};

[[nodiscard]] std::string_view to_string(SniError err) noexcept;

[[nodiscard]] std::expected<std::string_view, SniError> extract_sni(
    std::span<const std::uint8_t> data) noexcept;

}  // namespace l7wall::tls
