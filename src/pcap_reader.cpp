#include "l7wall/pcap_reader.hpp"

#include <format>
#include <fstream>
#include <iterator>

#include "l7wall/byte_order.hpp"

namespace l7wall {
namespace {

constexpr std::size_t kGlobalHeaderLen = 24;
constexpr std::size_t kRecordHeaderLen = 16;
// Guard against garbage lengths in corrupt files.
constexpr std::uint32_t kMaxRecordLen = 256 * 1024;

constexpr std::uint32_t kMagicMicros = 0xA1B2C3D4;
constexpr std::uint32_t kMagicMicrosSwapped = 0xD4C3B2A1;
constexpr std::uint32_t kMagicNanos = 0xA1B23C4D;
constexpr std::uint32_t kMagicNanosSwapped = 0x4D3CB2A1;
constexpr std::uint32_t kPcapngMagic = 0x0A0D0D0A;

}  // namespace

std::expected<PcapReader, std::string> PcapReader::open(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(std::format("cannot open '{}'", path.string()));
    }
    std::vector<std::uint8_t> buffer{std::istreambuf_iterator<char>(in),
                                     std::istreambuf_iterator<char>()};
    if (in.bad()) {
        return std::unexpected(std::format("failed to read '{}'", path.string()));
    }
    return from_buffer(std::move(buffer));
}

std::expected<PcapReader, std::string> PcapReader::from_buffer(std::vector<std::uint8_t> buffer) {
    if (buffer.size() < kGlobalHeaderLen) {
        return std::unexpected(std::string{"file too short for pcap global header"});
    }

    PcapReader reader;
    // Magic is read little-endian; a "swapped" value means the file is big-endian.
    switch (load_le32(buffer.data())) {
        case kMagicMicros:
            break;
        case kMagicMicrosSwapped:
            reader.swapped_ = true;
            break;
        case kMagicNanos:
            reader.nanosecond_ = true;
            break;
        case kMagicNanosSwapped:
            reader.swapped_ = true;
            reader.nanosecond_ = true;
            break;
        case kPcapngMagic:
            return std::unexpected(
                std::string{"pcapng is not supported yet, convert with: editcap -F pcap in out"});
        default:
            return std::unexpected(std::string{"not a pcap file (bad magic)"});
    }

    reader.buffer_ = std::move(buffer);
    reader.snaplen_ = reader.load_u32(16);
    reader.link_type_ = static_cast<LinkType>(reader.load_u32(20) & 0x0FFFFFFF);
    reader.offset_ = kGlobalHeaderLen;
    return reader;
}

std::expected<std::optional<PcapRecord>, std::string> PcapReader::next() {
    if (offset_ == buffer_.size()) {
        return std::nullopt;
    }
    if (buffer_.size() - offset_ < kRecordHeaderLen) {
        return std::unexpected(std::format("truncated record header at offset {}", offset_));
    }

    const std::uint32_t ts_sec = load_u32(offset_);
    const std::uint32_t ts_frac = load_u32(offset_ + 4);
    const std::uint32_t incl_len = load_u32(offset_ + 8);
    const std::uint32_t orig_len = load_u32(offset_ + 12);

    if (incl_len > kMaxRecordLen) {
        return std::unexpected(
            std::format("record at offset {} has implausible length {}", offset_, incl_len));
    }
    const std::size_t data_offset = offset_ + kRecordHeaderLen;
    if (buffer_.size() - data_offset < incl_len) {
        return std::unexpected(std::format("truncated record data at offset {}", offset_));
    }

    PcapRecord record;
    record.timestamp = std::chrono::seconds{ts_sec} +
                       (nanosecond_ ? std::chrono::nanoseconds{ts_frac}
                                    : std::chrono::microseconds{ts_frac});
    record.original_length = orig_len;
    record.data = std::span{buffer_}.subspan(data_offset, incl_len);

    offset_ = data_offset + incl_len;
    return record;
}

std::uint32_t PcapReader::load_u32(std::size_t offset) const noexcept {
    const std::uint8_t* p = buffer_.data() + offset;
    return swapped_ ? load_be32(p) : load_le32(p);
}

}  // namespace l7wall
