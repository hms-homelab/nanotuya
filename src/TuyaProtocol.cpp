#include "nanotuya/TuyaProtocol.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <iomanip>

namespace nanotuya {

// ─── Helpers ──────────────────────────────────────────────────────────────────

void TuyaProtocol::appendBE32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >>  8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >>  0) & 0xFF));
}

uint32_t TuyaProtocol::readBE32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           (static_cast<uint32_t>(p[3]));
}

std::string TuyaProtocol::timestamp() {
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return std::to_string(epoch);
}

// ─── CRC32 (zlib-compatible, polynomial 0xEDB88320) ──────────────────────────

static uint32_t* buildCrc32Table() {
    static uint32_t table[256];
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        table[i] = crc;
    }
    return table;
}

static const uint32_t* kCrc32Table = buildCrc32Table();

uint32_t TuyaProtocol::crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t b : data) {
        crc = kCrc32Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// ─── AES-128-ECB ─────────────────────────────────────────────────────────────

std::vector<uint8_t> TuyaProtocol::encryptECB(const std::string& key,
                                               const std::vector<uint8_t>& data) {
    if (key.size() != 16)
        throw std::runtime_error("AES key must be 16 bytes");

    // PKCS7 pad
    size_t pad_len = 16 - (data.size() % 16);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));

    std::vector<uint8_t> out(padded.size() + 16); // extra room
    int out_len = 0, final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    // We already did PKCS7 padding, disable OpenSSL's auto-padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_EncryptUpdate(ctx, out.data(), &out_len, padded.data(),
        static_cast<int>(padded.size()));
    EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(out_len + final_len);
    return out;
}

std::vector<uint8_t> TuyaProtocol::decryptECB(const std::string& key,
                                               const std::vector<uint8_t>& data) {
    if (key.size() != 16)
        throw std::runtime_error("AES key must be 16 bytes");
    if (data.empty() || data.size() % 16 != 0)
        throw std::runtime_error("Ciphertext must be multiple of 16 bytes");

    std::vector<uint8_t> out(data.size() + 16);
    int out_len = 0, final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    // We'll strip PKCS7 manually for robustness
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_DecryptUpdate(ctx, out.data(), &out_len, data.data(),
        static_cast<int>(data.size()));
    EVP_DecryptFinal_ex(ctx, out.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(out_len + final_len);

    // Strip PKCS7 padding
    if (!out.empty()) {
        uint8_t pad = out.back();
        if (pad > 0 && pad <= 16) {
            bool valid = true;
            for (size_t i = out.size() - pad; i < out.size(); ++i) {
                if (out[i] != pad) { valid = false; break; }
            }
            if (valid) out.resize(out.size() - pad);
        }
    }

    return out;
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────

std::vector<uint8_t> TuyaProtocol::hmacSHA256(const std::string& key,
                                               const std::vector<uint8_t>& data) {
    unsigned char result[32];
    unsigned int result_len = 32;

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         data.data(), data.size(),
         result, &result_len);

    return std::vector<uint8_t>(result, result + result_len);
}

// ─── MD5 ─────────────────────────────────────────────────────────────────────

std::string TuyaProtocol::md5hex(const std::vector<uint8_t>& data) {
    unsigned char digest[16];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    for (unsigned int i = 0; i < len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(digest[i]);
    return ss.str();
}

// ─── Base64 ──────────────────────────────────────────────────────────────────

std::string TuyaProtocol::base64Encode(const std::vector<uint8_t>& data) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i + 2]);

        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? table[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? table[n & 0x3F] : '=';
    }
    return result;
}

// ─── JSON payload generators ─────────────────────────────────────────────────

std::vector<uint8_t> TuyaProtocol::makeStatusPayload(const std::string& dev_id,
                                                      TuyaVersion version) {
    Json::Value root;
    std::string ts = timestamp();

    if (version == TuyaVersion::V34) {
        // v3.4 uses DP_QUERY_NEW format
        root["protocol"] = 5;
        root["t"] = static_cast<Json::Int64>(std::stoll(ts));
        root["data"] = Json::Value(Json::objectValue);
    } else {
        root["gwId"] = dev_id;
        root["devId"] = dev_id;
        root["uid"] = dev_id;
        root["t"] = ts;
    }

    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    std::string json = Json::writeString(wb, root);
    return std::vector<uint8_t>(json.begin(), json.end());
}

std::vector<uint8_t> TuyaProtocol::makeControlPayload(const std::string& dev_id,
                                                       const Json::Value& dps,
                                                       TuyaVersion version) {
    Json::Value root;
    std::string ts = timestamp();

    if (version == TuyaVersion::V34) {
        root["protocol"] = 5;
        root["t"] = static_cast<Json::Int64>(std::stoll(ts));
        Json::Value data;
        data["devId"] = dev_id;
        data["uid"] = dev_id;
        data["t"] = ts;
        data["dps"] = dps;
        root["data"] = data;
    } else {
        root["devId"] = dev_id;
        root["uid"] = dev_id;
        root["t"] = ts;
        root["dps"] = dps;
    }

    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    std::string json = Json::writeString(wb, root);
    return std::vector<uint8_t>(json.begin(), json.end());
}

// ─── buildMessage ────────────────────────────────────────────────────────────

std::vector<uint8_t> TuyaProtocol::buildMessage(uint32_t seqno, Command cmd,
    const std::vector<uint8_t>& payload, TuyaVersion version,
    const std::string& key) {

    std::vector<uint8_t> data_to_encrypt;

    if (version == TuyaVersion::V31) {
        // v3.1: only CONTROL commands are encrypted
        if (cmd == Command::CONTROL) {
            // Encrypt payload, base64 encode
            auto encrypted = encryptECB(key, payload);
            std::string b64 = base64Encode(encrypted);

            // MD5 signature: md5("data=" + b64 + "||lpv=3.1||" + key)[8:24]
            std::string sig_input = "data=" + b64 + "||lpv=3.1||" + key;
            std::vector<uint8_t> sig_bytes(sig_input.begin(), sig_input.end());
            std::string md5_full = md5hex(sig_bytes);
            std::string md5sig = md5_full.substr(8, 16);  // chars [8..24)

            // Build: version header "3.1" + md5sig(16 bytes) + b64payload
            auto vh = versionHeader(TuyaVersion::V31);
            data_to_encrypt.insert(data_to_encrypt.end(), vh.begin(), vh.end());
            data_to_encrypt.insert(data_to_encrypt.end(), md5sig.begin(), md5sig.end());
            data_to_encrypt.insert(data_to_encrypt.end(), b64.begin(), b64.end());
        } else {
            // Other commands: payload sent as-is (no encryption)
            data_to_encrypt = payload;
        }
    } else if (version == TuyaVersion::V33) {
        // v3.3: version header in cleartext, then encrypted payload
        auto encrypted = encryptECB(key, payload);
        if (needsVersionHeader(cmd)) {
            auto vh = versionHeader(TuyaVersion::V33);
            data_to_encrypt.insert(data_to_encrypt.end(), vh.begin(), vh.end());
        }
        data_to_encrypt.insert(data_to_encrypt.end(), encrypted.begin(), encrypted.end());
    } else {
        // v3.4: version header + payload encrypted together (with session key)
        std::vector<uint8_t> to_encrypt;
        if (needsVersionHeader(cmd)) {
            auto vh = versionHeader(TuyaVersion::V34);
            to_encrypt.insert(to_encrypt.end(), vh.begin(), vh.end());
        }
        to_encrypt.insert(to_encrypt.end(), payload.begin(), payload.end());
        data_to_encrypt = encryptECB(key, to_encrypt);
    }

    // Determine integrity field size
    bool use_hmac = (version == TuyaVersion::V34);
    uint32_t integrity_size = use_hmac ? 32 : 4;

    uint32_t length = static_cast<uint32_t>(data_to_encrypt.size())
                      + integrity_size + 4;

    std::vector<uint8_t> frame;
    frame.reserve(HEADER_SIZE + length);
    appendBE32(frame, PREFIX_55AA);
    appendBE32(frame, seqno);
    appendBE32(frame, static_cast<uint32_t>(cmd));
    appendBE32(frame, length);
    frame.insert(frame.end(), data_to_encrypt.begin(), data_to_encrypt.end());

    // Integrity
    if (use_hmac) {
        // HMAC-SHA256 over header(16) + retcode(4) + data
        // i.e., everything from prefix through encrypted data
        auto hmac = hmacSHA256(key, frame);
        frame.insert(frame.end(), hmac.begin(), hmac.end());
    } else {
        // CRC32 over everything from prefix through encrypted data
        uint32_t crc = TuyaProtocol::crc32(frame);
        appendBE32(frame, crc);
    }

    // Suffix
    appendBE32(frame, SUFFIX_AA55);

    return frame;
}

// ─── parseMessage ────────────────────────────────────────────────────────────

TuyaMessage TuyaProtocol::parseMessage(const std::vector<uint8_t>& data,
    TuyaVersion version, const std::string& key) {

    TuyaMessage msg;

    if (data.size() < HEADER_SIZE + 12) // minimum: header + retcode + crc + suffix
        throw std::runtime_error("Frame too short");

    // Verify prefix
    uint32_t prefix = readBE32(data.data());
    if (prefix != PREFIX_55AA)
        throw std::runtime_error("Invalid prefix");

    msg.seqno = readBE32(data.data() + 4);
    msg.cmd = static_cast<Command>(readBE32(data.data() + 8));
    uint32_t length = readBE32(data.data() + 12);

    // length includes everything after header: retcode + data + CRC/HMAC + suffix
    // Total frame = HEADER_SIZE + length
    if (data.size() < HEADER_SIZE + length)
        throw std::runtime_error("Frame truncated");

    // Verify suffix (last 4 bytes of the frame)
    uint32_t suffix = readBE32(data.data() + HEADER_SIZE + length - 4);
    if (suffix != SUFFIX_AA55)
        throw std::runtime_error("Invalid suffix");

    // Extract retcode (first 4 bytes after header)
    msg.retcode = readBE32(data.data() + HEADER_SIZE);

    // Determine integrity field size
    bool use_hmac = (version == TuyaVersion::V34);
    uint32_t integrity_size = use_hmac ? 32 : 4;

    // Layout after header: retcode(4) + encrypted_data(N) + integrity(4|32) + suffix(4)
    // length = 4 + N + integrity_size + 4
    if (length < 4 + integrity_size + 4)
        throw std::runtime_error("Length field too small");

    uint32_t enc_data_size = length - 4 - integrity_size - 4;
    const uint8_t* enc_data_ptr = data.data() + HEADER_SIZE + 4;
    const uint8_t* integrity_ptr = enc_data_ptr + enc_data_size;

    // Verify integrity
    if (use_hmac) {
        // HMAC over header(16) + retcode(4) + encrypted data
        std::vector<uint8_t> hmac_input(data.begin(),
            data.begin() + HEADER_SIZE + 4 + enc_data_size);
        auto expected_hmac = hmacSHA256(key, hmac_input);
        std::vector<uint8_t> received_hmac(integrity_ptr,
            integrity_ptr + 32);
        msg.integrity_ok = (expected_hmac == received_hmac);
    } else {
        // CRC32 over header + retcode + encrypted data
        std::vector<uint8_t> crc_input(data.begin(),
            data.begin() + HEADER_SIZE + 4 + enc_data_size);
        uint32_t expected_crc = TuyaProtocol::crc32(crc_input);
        uint32_t received_crc = readBE32(integrity_ptr);
        msg.integrity_ok = (expected_crc == received_crc);
    }

    // Handle empty payload (e.g., heartbeat response)
    if (enc_data_size == 0) {
        msg.payload.clear();
        return msg;
    }

    std::vector<uint8_t> encrypted(enc_data_ptr, enc_data_ptr + enc_data_size);

    if (version == TuyaVersion::V31 && msg.cmd != Command::CONTROL) {
        // v3.1 non-CONTROL responses: payload is plaintext
        msg.payload = encrypted;
    } else if (version == TuyaVersion::V33) {
        // v3.3: version header is cleartext (15 bytes), followed by encrypted data
        size_t offset = 0;
        if (enc_data_size >= 15 && encrypted[0] == '3' && encrypted[1] == '.') {
            offset = 15;  // skip cleartext version header
        }
        std::vector<uint8_t> enc_only(encrypted.begin() + offset, encrypted.end());
        if (enc_only.empty()) {
            msg.payload.clear();
        } else {
            msg.payload = decryptECB(key, enc_only);
        }
    } else {
        // v3.4: version header + payload encrypted together
        auto decrypted = decryptECB(key, encrypted);
        // Strip version header if present inside decrypted data
        if (decrypted.size() >= 15 && decrypted[0] == '3' && decrypted[1] == '.') {
            decrypted.erase(decrypted.begin(), decrypted.begin() + 15);
        }
        msg.payload = decrypted;
    }

    return msg;
}

} // namespace nanotuya
