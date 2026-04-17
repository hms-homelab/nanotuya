#include "nanotuya/TuyaDevice.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <cerrno>
#include <cstring>
#include <sstream>

namespace nanotuya {

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

TuyaDevice::TuyaDevice(const DeviceConfig& config)
    : config_(config)
    , active_key_(config.local_key) {}

TuyaDevice::~TuyaDevice() {
    disconnectSocket();
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

bool TuyaDevice::connectSocket() {
    sock_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) {
        last_error_ = std::string("socket() failed: ") + std::strerror(errno);
        return false;
    }

    // Disable Nagle (TCP_NODELAY)
    int flag = 1;
    ::setsockopt(sock_fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    // Set send/receive timeouts
    struct timeval tv{};
    tv.tv_sec = config_.timeout_ms / 1000;
    tv.tv_usec = (config_.timeout_ms % 1000) * 1000;
    ::setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(config_.port));

    if (::inet_pton(AF_INET, config_.ip.c_str(), &addr.sin_addr) != 1) {
        last_error_ = "Invalid IP address: " + config_.ip;
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    if (::connect(sock_fd_, reinterpret_cast<struct sockaddr*>(&addr),
                  sizeof(addr)) < 0) {
        last_error_ = "connect() to " + config_.ip + ":" +
                      std::to_string(config_.port) + " failed: " +
                      std::strerror(errno);
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    return true;
}

void TuyaDevice::disconnectSocket() {
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
}

bool TuyaDevice::sendAll(const std::vector<uint8_t>& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(sock_fd_, data.data() + sent, data.size() - sent,
                           MSG_NOSIGNAL);
        if (n <= 0) {
            last_error_ = std::string("send() failed: ") + std::strerror(errno);
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::vector<uint8_t> TuyaDevice::recvExact(size_t n) {
    std::vector<uint8_t> buf(n);
    size_t received = 0;
    while (received < n) {
        ssize_t r = ::recv(sock_fd_, buf.data() + received, n - received, 0);
        if (r <= 0) {
            last_error_ = std::string("recv() failed: ") + std::strerror(errno);
            return {};
        }
        received += static_cast<size_t>(r);
    }
    return buf;
}

// ---------------------------------------------------------------------------
// readFrame -- read a complete Tuya protocol frame from the socket
// ---------------------------------------------------------------------------

std::vector<uint8_t> TuyaDevice::readFrame() {
    // Read prefix (4 bytes) -- expect 0x000055AA
    auto prefix_bytes = recvExact(4);
    if (prefix_bytes.size() != 4) {
        last_error_ = "Failed to read frame prefix";
        return {};
    }

    uint32_t prefix = (static_cast<uint32_t>(prefix_bytes[0]) << 24) |
                      (static_cast<uint32_t>(prefix_bytes[1]) << 16) |
                      (static_cast<uint32_t>(prefix_bytes[2]) << 8) |
                      (static_cast<uint32_t>(prefix_bytes[3]));
    if (prefix != PREFIX_55AA) {
        std::ostringstream oss;
        oss << "Invalid frame prefix: 0x" << std::hex << prefix;
        last_error_ = oss.str();
        return {};
    }

    // Read seqno(4) + cmd(4) + length(4) = 12 bytes
    auto header_rest = recvExact(12);
    if (header_rest.size() != 12) {
        last_error_ = "Failed to read frame header";
        return {};
    }

    // Parse length (big-endian) from bytes 8..11 of header_rest
    uint32_t length = (static_cast<uint32_t>(header_rest[8]) << 24) |
                      (static_cast<uint32_t>(header_rest[9]) << 16) |
                      (static_cast<uint32_t>(header_rest[10]) << 8) |
                      (static_cast<uint32_t>(header_rest[11]));

    // Sanity check -- Tuya frames shouldn't be huge
    if (length > 65536) {
        last_error_ = "Frame length too large: " + std::to_string(length);
        return {};
    }

    // Read payload + return_code + crc/hmac + suffix
    // The length field includes retcode(4) + payload + crc/hmac(4 or 32) + suffix(4)
    auto payload_bytes = recvExact(length);
    if (payload_bytes.size() != length) {
        last_error_ = "Failed to read frame payload";
        return {};
    }

    // Verify suffix (last 4 bytes)
    if (length >= 4) {
        uint32_t suffix = (static_cast<uint32_t>(payload_bytes[length - 4]) << 24) |
                          (static_cast<uint32_t>(payload_bytes[length - 3]) << 16) |
                          (static_cast<uint32_t>(payload_bytes[length - 2]) << 8) |
                          (static_cast<uint32_t>(payload_bytes[length - 1]));
        if (suffix != SUFFIX_AA55) {
            std::ostringstream oss;
            oss << "Invalid frame suffix: 0x" << std::hex << suffix;
            last_error_ = oss.str();
            return {};
        }
    }

    // Assemble complete frame: prefix + header_rest + payload
    std::vector<uint8_t> frame;
    frame.reserve(4 + 12 + length);
    frame.insert(frame.end(), prefix_bytes.begin(), prefix_bytes.end());
    frame.insert(frame.end(), header_rest.begin(), header_rest.end());
    frame.insert(frame.end(), payload_bytes.begin(), payload_bytes.end());

    return frame;
}

// ---------------------------------------------------------------------------
// v3.4 Session Key Negotiation
// ---------------------------------------------------------------------------

bool TuyaDevice::negotiateSessionKey() {
    // Step 1: Generate 16-byte local nonce
    std::vector<uint8_t> local_nonce(16);
    if (RAND_bytes(local_nonce.data(), 16) != 1) {
        last_error_ = "RAND_bytes failed for local_nonce";
        return false;
    }

    // Send SESS_KEY_NEG_START with local_nonce (no encryption, CRC32)
    auto start_frame = TuyaProtocol::buildMessage(
        seqno_++, Command::SESS_KEY_NEG_START, local_nonce,
        config_.version, config_.local_key);
    if (!sendAll(start_frame)) return false;

    // Step 2: Receive SESS_KEY_NEG_RESP
    auto resp_data = readFrame();
    if (resp_data.empty()) {
        last_error_ = "No response to SESS_KEY_NEG_START";
        return false;
    }

    auto resp_msg = TuyaProtocol::parseMessage(resp_data, config_.version,
                                                config_.local_key);
    if (resp_msg.cmd != Command::SESS_KEY_NEG_RESP) {
        last_error_ = "Expected SESS_KEY_NEG_RESP, got cmd=" +
                      std::to_string(static_cast<uint32_t>(resp_msg.cmd));
        return false;
    }

    // parseMessage already decrypted the v3.4 payload
    auto& decrypted = resp_msg.payload;
    if (decrypted.size() < 48) {  // 16 bytes nonce + 32 bytes HMAC
        last_error_ = "SESS_KEY_NEG_RESP payload too short (" +
                      std::to_string(decrypted.size()) + " bytes)";
        return false;
    }

    // Extract remote_nonce (first 16 bytes) and hmac_check (next 32 bytes)
    std::vector<uint8_t> remote_nonce(decrypted.begin(), decrypted.begin() + 16);
    std::vector<uint8_t> hmac_check(decrypted.begin() + 16, decrypted.begin() + 48);

    // Verify: HMAC-SHA256(local_key, local_nonce) == hmac_check
    unsigned int hmac_len = 0;
    uint8_t expected_hmac[32];
    HMAC(EVP_sha256(),
         config_.local_key.data(), static_cast<int>(config_.local_key.size()),
         local_nonce.data(), local_nonce.size(),
         expected_hmac, &hmac_len);

    if (hmac_len != 32 ||
        std::memcmp(expected_hmac, hmac_check.data(), 32) != 0) {
        last_error_ = "HMAC verification failed in session negotiation";
        return false;
    }

    // Step 3: Send SESS_KEY_NEG_FINISH with HMAC-SHA256(local_key, remote_nonce)
    uint8_t finish_hmac[32];
    unsigned int finish_hmac_len = 0;
    HMAC(EVP_sha256(),
         config_.local_key.data(), static_cast<int>(config_.local_key.size()),
         remote_nonce.data(), remote_nonce.size(),
         finish_hmac, &finish_hmac_len);

    std::vector<uint8_t> finish_payload(finish_hmac, finish_hmac + 32);
    auto finish_frame = TuyaProtocol::buildMessage(
        seqno_++, Command::SESS_KEY_NEG_FINISH, finish_payload,
        config_.version, config_.local_key);
    if (!sendAll(finish_frame)) return false;

    // Derive session key: AES-ECB-encrypt(local_key, local_nonce XOR remote_nonce)
    std::vector<uint8_t> xored(16);
    for (int i = 0; i < 16; ++i) {
        xored[i] = local_nonce[i] ^ remote_nonce[i];
    }

    auto encrypted = TuyaProtocol::encryptECB(config_.local_key, xored);
    if (encrypted.size() < 16) {
        last_error_ = "Session key derivation failed";
        return false;
    }

    session_key_.assign(reinterpret_cast<const char*>(encrypted.data()), 16);
    active_key_ = session_key_;

    return true;
}

// ---------------------------------------------------------------------------
// sendReceive -- send a command and wait for response
// ---------------------------------------------------------------------------

std::optional<TuyaMessage> TuyaDevice::sendReceive(Command cmd,
    const std::vector<uint8_t>& payload) {

    auto frame = TuyaProtocol::buildMessage(seqno_++, cmd, payload,
                                             config_.version, active_key_);
    if (!sendAll(frame)) return std::nullopt;

    // Read response, retrying once if we get an empty/ACK payload
    for (int attempt = 0; attempt < 2; ++attempt) {
        auto resp_data = readFrame();
        if (resp_data.empty()) {
            if (attempt == 0) continue;
            last_error_ = "No response received";
            return std::nullopt;
        }

        auto msg = TuyaProtocol::parseMessage(resp_data, config_.version,
                                               active_key_);
        if (!msg.integrity_ok) {
            last_error_ = "Response integrity check failed";
            return std::nullopt;
        }

        // Skip empty ACK responses (retry to get the real data)
        if (msg.payload.empty() && attempt == 0) {
            continue;
        }

        return msg;
    }

    last_error_ = "No valid response after retries";
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Public persistent connection API
// ---------------------------------------------------------------------------

bool TuyaDevice::connect() {
    if (isConnected()) return true;

    seqno_ = 1;
    active_key_ = config_.local_key;

    if (!connectSocket()) return false;

    if (config_.version == TuyaVersion::V34) {
        if (!negotiateSessionKey()) {
            disconnectSocket();
            return false;
        }
    }

    return true;
}

void TuyaDevice::disconnect() {
    disconnectSocket();
    session_key_.clear();
    active_key_ = config_.local_key;
}

bool TuyaDevice::heartbeat() {
    if (!isConnected()) return false;

    auto frame = TuyaProtocol::buildMessage(
        seqno_++, Command::HEART_BEAT, {}, config_.version, active_key_);
    if (!sendAll(frame)) {
        disconnectSocket();
        return false;
    }

    auto resp_data = readFrame();
    if (resp_data.empty()) {
        disconnectSocket();
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// ensureConnected / cleanupIfEphemeral -- helpers for burst vs persistent
// ---------------------------------------------------------------------------

bool TuyaDevice::ensureConnected() {
    if (isConnected()) return true;

    seqno_ = 1;
    active_key_ = config_.local_key;

    if (!connectSocket()) return false;

    if (config_.version == TuyaVersion::V34) {
        if (!negotiateSessionKey()) {
            disconnectSocket();
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// queryStatus
// ---------------------------------------------------------------------------

std::optional<Json::Value> TuyaDevice::queryStatus() {
    bool was_connected = isConnected();

    for (int retry = 0; retry <= config_.retry_limit; ++retry) {
        if (!ensureConnected()) {
            continue;
        }

        auto payload = TuyaProtocol::makeStatusPayload(config_.id);
        Command cmd = (config_.version == TuyaVersion::V34)
                          ? Command::DP_QUERY_NEW
                          : Command::DP_QUERY;

        auto resp = sendReceive(cmd, payload);

        if (!resp) {
            disconnectSocket();
            continue;
        }

        if (resp->payload.empty()) {
            last_error_ = "Empty response payload";
            if (!was_connected) disconnectSocket();
            continue;
        }

        std::string json_str(resp->payload.begin(), resp->payload.end());

        Json::CharReaderBuilder builder;
        Json::Value root;
        std::istringstream stream(json_str);
        std::string parse_errors;
        if (!Json::parseFromStream(builder, stream, &root, &parse_errors)) {
            last_error_ = "JSON parse error: " + parse_errors;
            if (!was_connected) disconnectSocket();
            continue;
        }

        if (!was_connected) disconnectSocket();

        if (root.isMember("dps")) {
            return root["dps"];
        }

        last_error_ = "No 'dps' key in response";
        continue;
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// setValue / setValues
// ---------------------------------------------------------------------------

bool TuyaDevice::setValue(const std::string& dp_id, const Json::Value& value) {
    Json::Value dps;
    dps[dp_id] = value;
    return setValues(dps);
}

bool TuyaDevice::setValues(const Json::Value& dps) {
    bool was_connected = isConnected();

    for (int retry = 0; retry <= config_.retry_limit; ++retry) {
        if (!ensureConnected()) {
            continue;
        }

        auto payload = TuyaProtocol::makeControlPayload(config_.id, dps);
        Command cmd = (config_.version == TuyaVersion::V34)
                          ? Command::CONTROL_NEW
                          : Command::CONTROL;

        auto resp = sendReceive(cmd, payload);

        if (!resp) {
            disconnectSocket();
            continue;
        }

        if (!was_connected) disconnectSocket();
        return true;
    }

    return false;
}

} // namespace nanotuya
