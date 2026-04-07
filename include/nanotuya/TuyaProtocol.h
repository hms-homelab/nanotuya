#pragma once
#include "TuyaDefs.h"
#include <json/json.h>
#include <string>
#include <vector>
#include <cstdint>

namespace nanotuya {

/// Stateless protocol engine for Tuya local WiFi protocol.
/// Handles framing (55AA), encryption (AES-128-ECB), and integrity
/// (CRC32 for v3.1/v3.3, HMAC-SHA256 for v3.4).
class TuyaProtocol {
public:
    // ── Frame construction / parsing ──────────────────────────────

    /// Build a complete frame ready to send over TCP.
    static std::vector<uint8_t> buildMessage(uint32_t seqno, Command cmd,
        const std::vector<uint8_t>& payload, TuyaVersion version,
        const std::string& key);

    /// Parse a received frame, decrypt, verify integrity.
    static TuyaMessage parseMessage(const std::vector<uint8_t>& data,
        TuyaVersion version, const std::string& key);

    // ── JSON payload generators ───────────────────────────────────

    /// Generate DP_QUERY / DP_QUERY_NEW payload for status request.
    static std::vector<uint8_t> makeStatusPayload(const std::string& dev_id,
        TuyaVersion version = TuyaVersion::V33);

    /// Generate CONTROL / CONTROL_NEW payload with DPS values.
    static std::vector<uint8_t> makeControlPayload(const std::string& dev_id,
        const Json::Value& dps,
        TuyaVersion version = TuyaVersion::V33);

    // ── Crypto primitives ─────────────────────────────────────────

    /// AES-128-ECB encrypt with PKCS7 padding.
    static std::vector<uint8_t> encryptECB(const std::string& key,
        const std::vector<uint8_t>& data);

    /// AES-128-ECB decrypt and strip PKCS7 padding.
    static std::vector<uint8_t> decryptECB(const std::string& key,
        const std::vector<uint8_t>& data);

    /// CRC32 (zlib-compatible) over data.
    static uint32_t crc32(const std::vector<uint8_t>& data);

    /// HMAC-SHA256 keyed hash.
    static std::vector<uint8_t> hmacSHA256(const std::string& key,
        const std::vector<uint8_t>& data);

    /// MD5 hex digest of data.
    static std::string md5hex(const std::vector<uint8_t>& data);

    /// Base64 encode.
    static std::string base64Encode(const std::vector<uint8_t>& data);

private:
    /// Write a uint32_t in big-endian to a byte vector.
    static void appendBE32(std::vector<uint8_t>& buf, uint32_t val);

    /// Read a big-endian uint32_t from raw bytes.
    static uint32_t readBE32(const uint8_t* p);

    /// Get current unix timestamp as string.
    static std::string timestamp();
};

} // namespace nanotuya
