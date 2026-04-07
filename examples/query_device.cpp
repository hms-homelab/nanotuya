// Usage: ./query_device <ip> <local_key> <version>
// Example: ./query_device 192.168.2.37 "3gW!Pz1iNKI9(xxe" 3.3
//
// Queries a Tuya device on the local network and prints its DPS status.
// The device_id is auto-detected from the local_key (not needed for query).
// For simplicity, device_id defaults to a placeholder -- real usage should
// set it from tinytuya/tuya-cli device list output.

#include "nanotuya/TuyaDevice.h"
#include <iostream>
#include <string>
#include <cstring>

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <ip> <device_id> <local_key> [version]\n"
              << "\n"
              << "  ip         Device IP address (e.g. 192.168.2.37)\n"
              << "  device_id  20-char device ID from Tuya cloud\n"
              << "  local_key  16-char local encryption key\n"
              << "  version    Protocol version: 3.1, 3.3 (default), or 3.4\n"
              << "\n"
              << "Example:\n"
              << "  " << prog << " 192.168.2.37 bf3e9af16a0e5c7a3c 0123456789abcdef 3.3\n";
}

static nanotuya::TuyaVersion parseVersion(const std::string& v) {
    if (v == "3.1") return nanotuya::TuyaVersion::V31;
    if (v == "3.4") return nanotuya::TuyaVersion::V34;
    return nanotuya::TuyaVersion::V33;  // default
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    nanotuya::DeviceConfig config;
    config.ip = argv[1];
    config.id = argv[2];
    config.local_key = argv[3];
    config.version = (argc >= 5) ? parseVersion(argv[4]) : nanotuya::TuyaVersion::V33;
    config.timeout_ms = 5000;
    config.retry_limit = 2;

    std::cout << "Querying device at " << config.ip
              << " (id=" << config.id
              << ", version=" << argv[argc >= 5 ? 4 : 0] << ")\n";

    nanotuya::TuyaDevice device(config);
    auto result = device.queryStatus();

    if (!result) {
        std::cerr << "Error: " << device.lastError() << "\n";
        return 1;
    }

    // Pretty-print the JSON result
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "  ";
    std::cout << Json::writeString(writer, *result) << "\n";

    return 0;
}
