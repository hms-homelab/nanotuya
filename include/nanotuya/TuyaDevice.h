#pragma once
#include "nanotuya/TuyaDefs.h"
#include "nanotuya/TuyaProtocol.h"
#include <json/json.h>
#include <optional>
#include <string>
#include <vector>

namespace nanotuya {

class TuyaDevice {
public:
    explicit TuyaDevice(const DeviceConfig& config);
    ~TuyaDevice();

    // Non-copyable
    TuyaDevice(const TuyaDevice&) = delete;
    TuyaDevice& operator=(const TuyaDevice&) = delete;

    // High-level operations
    // Each call opens a fresh TCP connection, does handshake if v3.4, executes, closes.
    // This matches the proven pattern from the Python bridge -- persistent connections
    // are unreliable with Tuya devices.
    std::optional<Json::Value> queryStatus();
    bool setValue(const std::string& dp_id, const Json::Value& value);
    bool setValues(const Json::Value& dps);

    const DeviceConfig& config() const { return config_; }
    std::string lastError() const { return last_error_; }

private:
    bool connectSocket();
    void disconnectSocket();

    // v3.4 session key negotiation (3-step HMAC handshake)
    // Step 1: Send SESS_KEY_NEG_START with 16-byte local_nonce
    // Step 2: Receive SESS_KEY_NEG_RESP -- decrypt with local_key to get
    //         remote_nonce(16B) + hmac_check(32B)
    //         Verify: HMAC-SHA256(local_key, local_nonce) == hmac_check
    // Step 3: Send SESS_KEY_NEG_FINISH with HMAC-SHA256(local_key, remote_nonce)
    // Derive session_key: AES-ECB-encrypt(local_key, local_nonce XOR remote_nonce)
    bool negotiateSessionKey();

    // Send a message and wait for response
    std::optional<TuyaMessage> sendReceive(Command cmd,
        const std::vector<uint8_t>& payload);

    // Read a complete frame from socket (prefix-length based)
    std::vector<uint8_t> readFrame();

    // Send raw bytes to socket
    bool sendAll(const std::vector<uint8_t>& data);

    // Read exactly n bytes from socket
    std::vector<uint8_t> recvExact(size_t n);

    DeviceConfig config_;
    int sock_fd_ = -1;
    uint32_t seqno_ = 1;
    std::string session_key_;   // derived session key for v3.4
    std::string active_key_;    // points to local_key or session_key
    std::string last_error_;
};

} // namespace nanotuya
