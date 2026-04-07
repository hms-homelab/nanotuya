#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace nanotuya {

constexpr uint32_t TUYA_PORT = 6668;
constexpr uint32_t PREFIX_55AA = 0x000055AA;
constexpr uint32_t SUFFIX_AA55 = 0x0000AA55;
constexpr int HEADER_SIZE = 16;  // prefix(4) + seqno(4) + cmd(4) + length(4)

enum class TuyaVersion { V31, V33, V34 };
enum class DeviceType { Bulb, Switch };

// Command types from Tuya protocol
enum class Command : uint32_t {
    SESS_KEY_NEG_START = 3,
    SESS_KEY_NEG_RESP = 4,
    SESS_KEY_NEG_FINISH = 5,
    CONTROL = 7,
    STATUS = 8,
    HEART_BEAT = 9,
    DP_QUERY = 10,
    CONTROL_NEW = 13,
    DP_QUERY_NEW = 16,
    UPDATEDPS = 18
};

struct DeviceConfig {
    std::string id;
    std::string ip;
    std::string local_key;  // 16 bytes ASCII
    TuyaVersion version = TuyaVersion::V33;
    int port = 6668;
    int timeout_ms = 5000;
    int retry_limit = 2;
};

struct TuyaMessage {
    uint32_t seqno = 0;
    Command cmd = Command::STATUS;
    uint32_t retcode = 0;
    std::vector<uint8_t> payload;
    bool integrity_ok = false;
};

// Commands that DON'T get the version header prefix
inline bool needsVersionHeader(Command cmd) {
    return cmd != Command::SESS_KEY_NEG_START &&
           cmd != Command::SESS_KEY_NEG_RESP &&
           cmd != Command::SESS_KEY_NEG_FINISH &&
           cmd != Command::DP_QUERY &&
           cmd != Command::DP_QUERY_NEW &&
           cmd != Command::HEART_BEAT &&
           cmd != Command::UPDATEDPS;
}

// Version header bytes: "3.x" + 12 zero bytes = 15 bytes total
inline std::vector<uint8_t> versionHeader(TuyaVersion v) {
    std::vector<uint8_t> header(15, 0);
    switch (v) {
        case TuyaVersion::V31: header[0]='3'; header[1]='.'; header[2]='1'; break;
        case TuyaVersion::V33: header[0]='3'; header[1]='.'; header[2]='3'; break;
        case TuyaVersion::V34: header[0]='3'; header[1]='.'; header[2]='4'; break;
    }
    return header;
}

} // namespace nanotuya
