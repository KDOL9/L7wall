#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <format>
#include <iostream>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

#include "l7wall/flow_table.hpp"
#include "l7wall/packet.hpp"
#include "l7wall/pcap_reader.hpp"

namespace {

constexpr std::string_view kUsage = "usage: l7wall <capture.pcap> [--top N]\n";

struct Options {
    std::string path;
    std::size_t top = 20;
};

std::optional<Options> parse_args(int argc, char** argv) {
    Options opts;
    const std::vector<std::string_view> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--top" && i + 1 < args.size()) {
            const std::string_view value = args[++i];
            const auto [ptr, ec] = std::from_chars(value.begin(), value.end(), opts.top);
            if (ec != std::errc{} || ptr != value.end()) {
                return std::nullopt;
            }
        } else if (opts.path.empty() && !args[i].starts_with("--")) {
            opts.path = args[i];
        } else {
            return std::nullopt;
        }
    }
    if (opts.path.empty()) {
        return std::nullopt;
    }
    return opts;
}

std::string format_endpoint(const l7wall::Endpoint& ep, std::uint8_t protocol) {
    const bool has_ports = protocol == static_cast<std::uint8_t>(l7wall::IpProtocol::Tcp) ||
                           protocol == static_cast<std::uint8_t>(l7wall::IpProtocol::Udp);
    const std::string ip = ep.ip.to_string();
    if (!has_ports) {
        return ip;
    }
    return ep.ip.is_v4() ? std::format("{}:{}", ip, ep.port) : std::format("[{}]:{}", ip, ep.port);
}

}  // namespace

int main(int argc, char** argv) {
    const auto opts = parse_args(argc, argv);
    if (!opts) {
        std::cerr << kUsage;
        return EXIT_FAILURE;
    }

    auto reader = l7wall::PcapReader::open(opts->path);
    if (!reader) {
        std::cerr << "error: " << reader.error() << '\n';
        return EXIT_FAILURE;
    }

    l7wall::FlowTable table;
    std::size_t parsed = 0;
    std::map<std::string_view, std::size_t> errors;

    while (true) {
        auto record = reader->next();
        if (!record) {
            std::cerr << "error: " << record.error() << '\n';
            return EXIT_FAILURE;
        }
        if (!record->has_value()) {
            break;
        }
        const l7wall::PcapRecord& rec = **record;
        const auto packet = l7wall::parse_packet(rec.data, reader->link_type());
        if (!packet) {
            ++errors[l7wall::to_string(packet.error())];
            continue;
        }
        ++parsed;
        table.update(*packet, rec.timestamp, rec.original_length);
    }

    std::size_t skipped = 0;
    for (const auto& [reason, count] : errors) {
        skipped += count;
    }
    std::cout << std::format("packets: {} parsed, {} skipped\n", parsed, skipped);
    for (const auto& [reason, count] : errors) {
        std::cout << std::format("  {:<24} {}\n", reason, count);
    }
    std::cout << std::format("flows:   {}\n\n", table.size());

    std::vector<const l7wall::Flow*> flows;
    flows.reserve(table.size());
    table.for_each([&](const l7wall::Flow& flow) { flows.push_back(&flow); });
    std::ranges::sort(flows, std::ranges::greater{}, &l7wall::Flow::total_bytes);

    std::cout << std::format("{:<7} {:<24} {:<24} {:<12} {:>8} {:>10} {:>8}\n", "PROTO",
                             "CLIENT", "SERVER", "STATE", "PKTS", "BYTES", "DUR(ms)");
    for (const l7wall::Flow* flow : flows | std::views::take(opts->top)) {
        const auto duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(flow->last_seen - flow->first_seen);
        const bool is_tcp = flow->protocol == static_cast<std::uint8_t>(l7wall::IpProtocol::Tcp);
        std::cout << std::format("{:<7} {:<24} {:<24} {:<12} {:>8} {:>10} {:>8}\n",
                                 l7wall::protocol_name(flow->protocol),
                                 format_endpoint(flow->client, flow->protocol),
                                 format_endpoint(flow->server, flow->protocol),
                                 is_tcp ? l7wall::to_string(flow->tcp_state) : "-",
                                 flow->total_packets(), flow->total_bytes(), duration.count());
    }
    return EXIT_SUCCESS;
}
