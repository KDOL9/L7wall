#include "l7wall/tls.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "frame_builder.hpp"

namespace l7wall::tls {
namespace {

using test::Bytes;
using test::append;
using test::push_be16;

struct Extension {
    std::uint16_t type = 0;
    Bytes body;
};

Extension server_name(std::string_view host, std::uint8_t name_type = 0) {
    Bytes entry;
    entry.push_back(name_type);
    push_be16(entry, static_cast<std::uint16_t>(host.size()));
    entry.insert(entry.end(), host.begin(), host.end());

    Extension ext{.type = 0x0000, .body = {}};
    push_be16(ext.body, static_cast<std::uint16_t>(entry.size()));
    append(ext.body, entry);
    return ext;
}

Extension supported_versions() {
    return {.type = 0x002b, .body = {0x04, 0x03, 0x04, 0x03, 0x03}};
}

Bytes client_hello(const std::vector<Extension>& extensions, bool with_extensions = true) {
    Bytes hello;
    push_be16(hello, 0x0303);
    hello.insert(hello.end(), 32, 0x42);
    hello.push_back(32);
    hello.insert(hello.end(), 32, 0x07);
    push_be16(hello, 4);
    push_be16(hello, 0x1301);
    push_be16(hello, 0x1302);
    hello.push_back(1);
    hello.push_back(0);

    if (with_extensions) {
        Bytes ext_block;
        for (const Extension& ext : extensions) {
            push_be16(ext_block, ext.type);
            push_be16(ext_block, static_cast<std::uint16_t>(ext.body.size()));
            append(ext_block, ext.body);
        }
        push_be16(hello, static_cast<std::uint16_t>(ext_block.size()));
        append(hello, ext_block);
    }

    Bytes handshake{0x01, 0, 0, 0};
    handshake[2] = static_cast<std::uint8_t>(hello.size() >> 8);
    handshake[3] = static_cast<std::uint8_t>(hello.size());
    append(handshake, hello);

    Bytes record{0x16, 0x03, 0x01};
    push_be16(record, static_cast<std::uint16_t>(handshake.size()));
    append(record, handshake);
    return record;
}

TEST(ExtractSni, ReturnsHostName) {
    const Bytes data = client_hello({server_name("www.example.com")});

    const auto sni = extract_sni(data);

    ASSERT_TRUE(sni) << to_string(sni.error());
    EXPECT_EQ(*sni, "www.example.com");
}

TEST(ExtractSni, FindsServerNameAfterOtherExtensions) {
    const Bytes data = client_hello({supported_versions(), server_name("kaspersky.com")});

    const auto sni = extract_sni(data);

    ASSERT_TRUE(sni);
    EXPECT_EQ(*sni, "kaspersky.com");
}

TEST(ExtractSni, IgnoresTrailingBytesAfterRecord) {
    Bytes data = client_hello({server_name("a.b")});
    data.push_back(0x17);

    EXPECT_EQ(extract_sni(data).value_or(""), "a.b");
}

TEST(ExtractSni, ReportsMissingServerName) {
    EXPECT_EQ(extract_sni(client_hello({supported_versions()})).error(), SniError::NoSni);
    EXPECT_EQ(extract_sni(client_hello({}, false)).error(), SniError::NoSni);
}

TEST(ExtractSni, SkipsNonHostNameEntries) {
    EXPECT_EQ(extract_sni(client_hello({server_name("x", 1)})).error(), SniError::NoSni);
}

TEST(ExtractSni, RejectsPlainHttp) {
    const std::string_view request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const Bytes data(request.begin(), request.end());

    EXPECT_EQ(extract_sni(data).error(), SniError::NotTls);
}

TEST(ExtractSni, RejectsOtherHandshakeMessages) {
    Bytes data = client_hello({server_name("example.com")});
    data[5] = 0x02;

    EXPECT_EQ(extract_sni(data).error(), SniError::NotClientHello);
}

TEST(ExtractSni, ReportsIncompleteForEveryPrefix) {
    const Bytes data = client_hello({supported_versions(), server_name("www.example.com")});

    for (std::size_t len = 0; len < data.size(); ++len) {
        const auto sni = extract_sni(std::span{data}.first(len));
        ASSERT_FALSE(sni) << "len=" << len;
        EXPECT_EQ(sni.error(), SniError::Incomplete) << "len=" << len;
    }
}

TEST(ExtractSni, RejectsExtensionLengthOverflow) {
    Bytes data = client_hello({server_name("example.com")});
    const std::size_t ext_len_offset = data.size() - server_name("example.com").body.size() - 2;
    data[ext_len_offset] = 0xFF;

    EXPECT_EQ(extract_sni(data).error(), SniError::Malformed);
}

TEST(ExtractSni, RejectsTooShortRecord) {
    const Bytes data{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00};

    EXPECT_EQ(extract_sni(data).error(), SniError::Malformed);
}

}  // namespace
}  // namespace l7wall::tls
