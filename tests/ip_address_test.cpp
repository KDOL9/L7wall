#include "l7wall/ip_address.hpp"

#include <gtest/gtest.h>

namespace l7wall {
namespace {

IpAddress make_v6(std::array<std::uint16_t, 8> groups) {
    std::array<std::uint8_t, 16> bytes{};
    for (std::size_t i = 0; i < groups.size(); ++i) {
        bytes[i * 2] = static_cast<std::uint8_t>(groups[i] >> 8);
        bytes[i * 2 + 1] = static_cast<std::uint8_t>(groups[i]);
    }
    return IpAddress::v6(bytes);
}

TEST(IpAddress, FormatsIpv4) {
    EXPECT_EQ(IpAddress::v4(192, 168, 0, 1).to_string(), "192.168.0.1");
    EXPECT_EQ(IpAddress::v4(0, 0, 0, 0).to_string(), "0.0.0.0");
}

TEST(IpAddress, FormatsIpv6WithZeroCompression) {
    EXPECT_EQ(make_v6({0, 0, 0, 0, 0, 0, 0, 1}).to_string(), "::1");
    EXPECT_EQ(make_v6({0, 0, 0, 0, 0, 0, 0, 0}).to_string(), "::");
    EXPECT_EQ(make_v6({0xfe80, 0, 0, 0, 0, 0, 0, 1}).to_string(), "fe80::1");
    EXPECT_EQ(make_v6({0x2001, 0xdb8, 0, 0, 1, 0, 0, 1}).to_string(), "2001:db8::1:0:0:1");
    EXPECT_EQ(make_v6({1, 0, 0, 0, 0, 0, 0, 0}).to_string(), "1::");
}

TEST(IpAddress, DoesNotCompressSingleZeroGroup) {
    EXPECT_EQ(make_v6({0x2001, 0xdb8, 0, 1, 1, 1, 1, 1}).to_string(), "2001:db8:0:1:1:1:1:1");
}

TEST(IpAddress, ComparesByFamilyAndBytes) {
    EXPECT_EQ(IpAddress::v4(10, 0, 0, 1), IpAddress::v4(10, 0, 0, 1));
    EXPECT_NE(IpAddress::v4(10, 0, 0, 1), IpAddress::v4(10, 0, 0, 2));
    EXPECT_LT(IpAddress::v4(10, 0, 0, 1), IpAddress::v4(10, 0, 0, 2));
    EXPECT_NE(IpAddress::v4(0, 0, 0, 0), make_v6({0, 0, 0, 0, 0, 0, 0, 0}));
}

TEST(IpAddress, EqualAddressesHashEqually) {
    EXPECT_EQ(IpAddress::v4(1, 2, 3, 4).hash(), IpAddress::v4(1, 2, 3, 4).hash());
}

}  // namespace
}  // namespace l7wall
