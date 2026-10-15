#include "l7wall/tls.hpp"

#include <algorithm>
#include <optional>

#include "l7wall/byte_order.hpp"

namespace l7wall::tls {
namespace {

using Bytes = std::span<const std::uint8_t>;

constexpr std::uint8_t kContentTypeHandshake = 0x16;
constexpr std::uint8_t kHandshakeClientHello = 0x01;
constexpr std::uint16_t kExtensionServerName = 0x0000;
constexpr std::uint8_t kNameTypeHostName = 0x00;
constexpr std::size_t kRecordHeaderLen = 5;
constexpr std::size_t kHandshakeHeaderLen = 4;
constexpr std::size_t kRandomLen = 32;
constexpr std::size_t kMaxHostNameLen = 255;

class Reader {
public:
    explicit Reader(Bytes data) noexcept : data_(data) {}

    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size(); }

    std::optional<std::uint8_t> u8() noexcept {
        if (data_.empty()) {
            return std::nullopt;
        }
        const std::uint8_t v = data_[0];
        data_ = data_.subspan(1);
        return v;
    }

    std::optional<std::uint16_t> u16() noexcept {
        if (data_.size() < 2) {
            return std::nullopt;
        }
        const std::uint16_t v = load_be16(data_.data());
        data_ = data_.subspan(2);
        return v;
    }

    std::optional<Bytes> bytes(std::size_t n) noexcept {
        if (data_.size() < n) {
            return std::nullopt;
        }
        const Bytes v = data_.first(n);
        data_ = data_.subspan(n);
        return v;
    }

    std::optional<Bytes> u8_prefixed() noexcept {
        const auto len = u8();
        return len ? bytes(*len) : std::nullopt;
    }

    std::optional<Bytes> u16_prefixed() noexcept {
        const auto len = u16();
        return len ? bytes(*len) : std::nullopt;
    }

private:
    Bytes data_;
};

std::expected<std::string_view, SniError> find_host_name(Bytes server_name_ext) noexcept {
    Reader ext(server_name_ext);
    const auto list = ext.u16_prefixed();
    if (!list) {
        return std::unexpected(SniError::Malformed);
    }
    Reader names(*list);
    while (names.remaining() > 0) {
        const auto type = names.u8();
        const auto name = names.u16_prefixed();
        if (!type || !name) {
            return std::unexpected(SniError::Malformed);
        }
        if (*type != kNameTypeHostName) {
            continue;
        }
        if (name->empty() || name->size() > kMaxHostNameLen) {
            return std::unexpected(SniError::Malformed);
        }
        return std::string_view(reinterpret_cast<const char*>(name->data()), name->size());
    }
    return std::unexpected(SniError::NoSni);
}

std::expected<std::string_view, SniError> parse_client_hello(Bytes hello) noexcept {
    Reader r(hello);
    if (!r.u16() || !r.bytes(kRandomLen) || !r.u8_prefixed() || !r.u16_prefixed() ||
        !r.u8_prefixed()) {
        return std::unexpected(SniError::Malformed);
    }
    if (r.remaining() == 0) {
        return std::unexpected(SniError::NoSni);
    }

    const auto extensions = r.u16_prefixed();
    if (!extensions) {
        return std::unexpected(SniError::Malformed);
    }
    Reader ext(*extensions);
    while (ext.remaining() > 0) {
        const auto type = ext.u16();
        const auto body = ext.u16_prefixed();
        if (!type || !body) {
            return std::unexpected(SniError::Malformed);
        }
        if (*type == kExtensionServerName) {
            return find_host_name(*body);
        }
    }
    return std::unexpected(SniError::NoSni);
}

}  // namespace

std::expected<std::string_view, SniError> extract_sni(std::span<const std::uint8_t> data) noexcept {
    if (data.empty()) {
        return std::unexpected(SniError::Incomplete);
    }
    if (data[0] != kContentTypeHandshake) {
        return std::unexpected(SniError::NotTls);
    }
    if (data.size() >= 2 && data[1] != 0x03) {
        return std::unexpected(SniError::NotTls);
    }
    if (data.size() < kRecordHeaderLen + kHandshakeHeaderLen) {
        return std::unexpected(SniError::Incomplete);
    }

    const std::size_t record_len = load_be16(&data[3]);
    if (record_len < kHandshakeHeaderLen) {
        return std::unexpected(SniError::Malformed);
    }
    const Bytes record =
        data.subspan(kRecordHeaderLen, std::min(record_len, data.size() - kRecordHeaderLen));
    if (record[0] != kHandshakeClientHello) {
        return std::unexpected(SniError::NotClientHello);
    }

    const std::size_t hello_len =
        (std::size_t{record[1]} << 16) | (std::size_t{record[2]} << 8) | record[3];
    if (hello_len > record.size() - kHandshakeHeaderLen) {
        return std::unexpected(SniError::Incomplete);
    }
    return parse_client_hello(record.subspan(kHandshakeHeaderLen, hello_len));
}

std::string_view to_string(SniError err) noexcept {
    switch (err) {
        case SniError::NotTls:
            return "not TLS";
        case SniError::NotClientHello:
            return "not a ClientHello";
        case SniError::Incomplete:
            return "incomplete ClientHello";
        case SniError::Malformed:
            return "malformed ClientHello";
        case SniError::NoSni:
            return "no SNI";
    }
    return "unknown";
}

}  // namespace l7wall::tls
