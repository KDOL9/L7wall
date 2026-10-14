#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "l7wall/packet.hpp"

namespace l7wall {

struct PcapRecord {
    Timestamp timestamp{};
    std::uint32_t original_length = 0;   // length on the wire
    std::span<const std::uint8_t> data;  // captured bytes, may be shorter than original_length
};

// Reader for the classic libpcap file format (not pcapng). Handles both byte orders and
// both microsecond and nanosecond timestamp variants. The whole file is held in memory;
// record spans stay valid for the lifetime of the reader.
class PcapReader {
public:
    [[nodiscard]] static std::expected<PcapReader, std::string> open(
        const std::filesystem::path& path);
    [[nodiscard]] static std::expected<PcapReader, std::string> from_buffer(
        std::vector<std::uint8_t> buffer);

    [[nodiscard]] LinkType link_type() const noexcept { return link_type_; }
    [[nodiscard]] std::uint32_t snaplen() const noexcept { return snaplen_; }

    // Next record, std::nullopt at end of file, or an error if the file is corrupt.
    [[nodiscard]] std::expected<std::optional<PcapRecord>, std::string> next();

private:
    PcapReader() = default;

    [[nodiscard]] std::uint32_t load_u32(std::size_t offset) const noexcept;

    std::vector<std::uint8_t> buffer_;
    std::size_t offset_ = 0;
    bool swapped_ = false;
    bool nanosecond_ = false;
    std::uint32_t snaplen_ = 0;
    LinkType link_type_ = LinkType::Ethernet;
};

}  // namespace l7wall
