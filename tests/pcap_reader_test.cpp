#include "l7wall/pcap_reader.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "frame_builder.hpp"

namespace l7wall {
namespace {

using namespace l7wall::test;
using namespace std::chrono_literals;

const std::vector<PcapFrame> kFrames{
    {.ts_sec = 1700000000, .ts_frac = 250, .data = {1, 2, 3}},
    {.ts_sec = 1700000001, .ts_frac = 0, .data = {4, 5, 6, 7}},
};

void expect_records(PcapReader& reader, Timestamp first_frac) {
    auto first = reader.next();
    ASSERT_TRUE(first && first->has_value());
    EXPECT_EQ((*first)->timestamp, 1700000000s + first_frac);
    EXPECT_TRUE(std::ranges::equal((*first)->data, kFrames[0].data));

    auto second = reader.next();
    ASSERT_TRUE(second && second->has_value());
    EXPECT_EQ((*second)->original_length, 4u);
    EXPECT_TRUE(std::ranges::equal((*second)->data, kFrames[1].data));

    auto end = reader.next();
    ASSERT_TRUE(end);
    EXPECT_FALSE(end->has_value());
}

TEST(PcapReader, ReadsLittleEndianMicrosecondFile) {
    auto reader = PcapReader::from_buffer(pcap_file(kFrames));

    ASSERT_TRUE(reader) << reader.error();
    EXPECT_EQ(reader->link_type(), LinkType::Ethernet);
    EXPECT_EQ(reader->snaplen(), 65535u);
    expect_records(*reader, 250us);
}

TEST(PcapReader, ReadsBigEndianNanosecondFile) {
    auto reader = PcapReader::from_buffer(
        pcap_file(kFrames, {.big_endian = true, .nanosecond = true, .link_type = 101}));

    ASSERT_TRUE(reader) << reader.error();
    EXPECT_EQ(reader->link_type(), LinkType::Raw);
    expect_records(*reader, 250ns);
}

TEST(PcapReader, RejectsBadMagic) {
    Bytes data = pcap_file(kFrames);
    data[0] = 0;

    EXPECT_FALSE(PcapReader::from_buffer(data));
}

TEST(PcapReader, RejectsPcapng) {
    Bytes data(32, 0);
    push_le32(data, 0);
    data[0] = 0x0A;
    data[1] = 0x0D;
    data[2] = 0x0D;
    data[3] = 0x0A;

    const auto reader = PcapReader::from_buffer(data);

    ASSERT_FALSE(reader);
    EXPECT_NE(reader.error().find("pcapng"), std::string::npos);
}

TEST(PcapReader, ReportsTruncatedRecord) {
    Bytes data = pcap_file(kFrames);
    data.pop_back();
    auto reader = PcapReader::from_buffer(data);
    ASSERT_TRUE(reader);

    ASSERT_TRUE(reader->next());
    EXPECT_FALSE(reader->next());
}

TEST(PcapReader, OpensFileFromDisk) {
    const auto path = std::filesystem::temp_directory_path() / "l7wall_pcap_reader_test.pcap";
    {
        const Bytes data = pcap_file(kFrames);
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }

    auto reader = PcapReader::open(path);
    std::filesystem::remove(path);

    ASSERT_TRUE(reader) << reader.error();
    expect_records(*reader, 250us);
}

TEST(PcapReader, ReportsMissingFile) {
    EXPECT_FALSE(PcapReader::open("/nonexistent/capture.pcap"));
}

}  // namespace
}  // namespace l7wall
