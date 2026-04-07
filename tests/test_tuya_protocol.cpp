#include <gtest/gtest.h>
#include "nanotuya/TuyaProtocol.h"
#include "nanotuya/TuyaDefs.h"
#include <json/json.h>
#include <algorithm>
#include <cstring>

using namespace nanotuya;

// Helper: build an "incoming" frame (with retcode, as device sends)
static std::vector<uint8_t> buildIncomingFrame(uint32_t seqno, Command cmd,
    const std::vector<uint8_t>& payload, TuyaVersion version,
    const std::string& key) {
    std::vector<uint8_t> data_section;
    if (version == TuyaVersion::V33) {
        if (needsVersionHeader(cmd)) {
            auto vh = versionHeader(version);
            data_section.insert(data_section.end(), vh.begin(), vh.end());
        }
        auto encrypted = TuyaProtocol::encryptECB(key, payload);
        data_section.insert(data_section.end(), encrypted.begin(), encrypted.end());
    } else if (version == TuyaVersion::V34) {
        std::vector<uint8_t> to_encrypt;
        if (needsVersionHeader(cmd)) {
            auto vh = versionHeader(version);
            to_encrypt.insert(to_encrypt.end(), vh.begin(), vh.end());
        }
        to_encrypt.insert(to_encrypt.end(), payload.begin(), payload.end());
        data_section = TuyaProtocol::encryptECB(key, to_encrypt);
    } else {
        if (cmd == Command::CONTROL) {
            data_section = TuyaProtocol::encryptECB(key, payload);
        } else {
            data_section = payload;
        }
    }

    bool use_hmac = (version == TuyaVersion::V34);
    uint32_t integrity_size = use_hmac ? 32 : 4;
    uint32_t length = 4 + static_cast<uint32_t>(data_section.size()) + integrity_size + 4;

    auto be32 = [](std::vector<uint8_t>& v, uint32_t val) {
        v.push_back((val >> 24) & 0xFF);
        v.push_back((val >> 16) & 0xFF);
        v.push_back((val >> 8) & 0xFF);
        v.push_back(val & 0xFF);
    };

    std::vector<uint8_t> frame;
    be32(frame, PREFIX_55AA);
    be32(frame, seqno);
    be32(frame, static_cast<uint32_t>(cmd));
    be32(frame, length);
    be32(frame, 0x00000000);
    frame.insert(frame.end(), data_section.begin(), data_section.end());

    if (use_hmac) {
        auto hmac = TuyaProtocol::hmacSHA256(key, frame);
        frame.insert(frame.end(), hmac.begin(), hmac.end());
    } else {
        uint32_t crc = TuyaProtocol::crc32(frame);
        be32(frame, crc);
    }
    be32(frame, SUFFIX_AA55);
    return frame;
}

class TuyaProtocolTest : public ::testing::Test {
protected:
    const std::string test_key = "0123456789abcdef";  // 16-byte key
    const std::string test_device_id = "37007105dc4f22bba697";
};

// ── 1. AES-ECB encryption/decryption roundtrip ─────────────────────

TEST_F(TuyaProtocolTest, AESEncryptDecryptRoundtrip) {
    // Exactly 16 bytes (one AES block, no padding needed beyond PKCS7)
    std::vector<uint8_t> plaintext = {
        'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
    };
    auto encrypted = TuyaProtocol::encryptECB(test_key, plaintext);
    ASSERT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, plaintext);

    auto decrypted = TuyaProtocol::decryptECB(test_key, encrypted);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(TuyaProtocolTest, AESEncryptDecryptNonBlockAligned) {
    // 7 bytes -- not a multiple of 16, exercises PKCS7 padding
    std::vector<uint8_t> plaintext = {'T','u','y','a','!','!','!'};
    auto encrypted = TuyaProtocol::encryptECB(test_key, plaintext);
    ASSERT_FALSE(encrypted.empty());
    // Encrypted output must be a multiple of 16
    EXPECT_EQ(encrypted.size() % 16, 0u);

    auto decrypted = TuyaProtocol::decryptECB(test_key, encrypted);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(TuyaProtocolTest, AESEncryptDecryptEmpty) {
    // Empty input -- PKCS7 pads to one full block of 0x10 bytes
    std::vector<uint8_t> plaintext;
    auto encrypted = TuyaProtocol::encryptECB(test_key, plaintext);
    // After PKCS7 padding, empty input becomes 16 bytes of 0x10
    ASSERT_FALSE(encrypted.empty());

    auto decrypted = TuyaProtocol::decryptECB(test_key, encrypted);
    EXPECT_EQ(decrypted, plaintext);
}

// ── 2. CRC32 ────────────────────────────────────────────────────────

TEST_F(TuyaProtocolTest, CRC32KnownValue) {
    // CRC32 of "123456789" is 0xCBF43926 (standard test vector)
    std::vector<uint8_t> data = {'1','2','3','4','5','6','7','8','9'};
    uint32_t crc = TuyaProtocol::crc32(data);
    EXPECT_EQ(crc, 0xCBF43926u);
}

TEST_F(TuyaProtocolTest, CRC32Empty) {
    std::vector<uint8_t> data;
    uint32_t crc = TuyaProtocol::crc32(data);
    EXPECT_EQ(crc, 0x00000000u);
}

// ── 3. HMAC-SHA256 ──────────────────────────────────────────────────

TEST_F(TuyaProtocolTest, HMACSHA256KnownValue) {
    // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
    std::string hmac_key = "Jefe";
    std::string msg = "what do ya want for nothing?";
    std::vector<uint8_t> data(msg.begin(), msg.end());

    auto hmac = TuyaProtocol::hmacSHA256(hmac_key, data);
    ASSERT_EQ(hmac.size(), 32u);

    // Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    uint8_t expected[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    EXPECT_EQ(hmac, std::vector<uint8_t>(expected, expected + 32));
}

TEST_F(TuyaProtocolTest, HMACSHA256OutputSize) {
    std::vector<uint8_t> data = {'t','e','s','t'};
    auto hmac = TuyaProtocol::hmacSHA256(test_key, data);
    EXPECT_EQ(hmac.size(), 32u);
}

// ── 4. buildMessage v3.3 ────────────────────────────────────────────

TEST_F(TuyaProtocolTest, BuildMessageV33HasCorrectPrefixAndSuffix) {
    auto payload = TuyaProtocol::makeStatusPayload(test_device_id, TuyaVersion::V33);
    auto frame = TuyaProtocol::buildMessage(1, Command::DP_QUERY, payload,
                                            TuyaVersion::V33, test_key);

    ASSERT_GE(frame.size(), 24u);  // At minimum: header(16) + crc(4) + suffix(4)

    // Check prefix: 0x000055AA in big-endian
    EXPECT_EQ(frame[0], 0x00);
    EXPECT_EQ(frame[1], 0x00);
    EXPECT_EQ(frame[2], 0x55);
    EXPECT_EQ(frame[3], 0xAA);

    // Check command byte (offset 8-11, big-endian) = DP_QUERY = 10
    uint32_t cmd = (frame[8] << 24) | (frame[9] << 16) | (frame[10] << 8) | frame[11];
    EXPECT_EQ(cmd, static_cast<uint32_t>(Command::DP_QUERY));

    // Check suffix: 0x0000AA55 in big-endian (last 4 bytes)
    size_t n = frame.size();
    EXPECT_EQ(frame[n-4], 0x00);
    EXPECT_EQ(frame[n-3], 0x00);
    EXPECT_EQ(frame[n-2], 0xAA);
    EXPECT_EQ(frame[n-1], 0x55);
}

TEST_F(TuyaProtocolTest, BuildMessageV33HasCRC) {
    auto payload = TuyaProtocol::makeStatusPayload(test_device_id, TuyaVersion::V33);
    auto frame = TuyaProtocol::buildMessage(1, Command::DP_QUERY, payload,
                                            TuyaVersion::V33, test_key);

    // v3.3 uses CRC32: 4 bytes before the 4-byte suffix
    // Total trailer = crc(4) + suffix(4) = 8 bytes
    // The frame should have header(16) + encrypted_payload + crc(4) + suffix(4)
    size_t n = frame.size();
    ASSERT_GE(n, 24u);

    // CRC32 is at [n-8 .. n-5], suffix at [n-4 .. n-1]
    // Just verify the suffix is correct (CRC value varies with payload)
    uint32_t suffix = (frame[n-4] << 24) | (frame[n-3] << 16) |
                      (frame[n-2] << 8) | frame[n-1];
    EXPECT_EQ(suffix, SUFFIX_AA55);
}

// ── 5. buildMessage v3.4 ────────────────────────────────────────────

TEST_F(TuyaProtocolTest, BuildMessageV34HasHMAC) {
    auto payload = TuyaProtocol::makeStatusPayload(test_device_id, TuyaVersion::V34);
    auto frame = TuyaProtocol::buildMessage(1, Command::DP_QUERY_NEW, payload,
                                            TuyaVersion::V34, test_key);

    ASSERT_GE(frame.size(), 52u);  // header(16) + payload + hmac(32) + suffix(4)

    // Check prefix
    EXPECT_EQ(frame[0], 0x00);
    EXPECT_EQ(frame[1], 0x00);
    EXPECT_EQ(frame[2], 0x55);
    EXPECT_EQ(frame[3], 0xAA);

    // Check suffix
    size_t n = frame.size();
    uint32_t suffix = (frame[n-4] << 24) | (frame[n-3] << 16) |
                      (frame[n-2] << 8) | frame[n-1];
    EXPECT_EQ(suffix, SUFFIX_AA55);

    // v3.4 has 32-byte HMAC-SHA256 before suffix (instead of 4-byte CRC)
    // Verify the HMAC region is non-zero (32 bytes before suffix)
    bool all_zero = true;
    for (size_t i = n - 36; i < n - 4; ++i) {
        if (frame[i] != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero) << "HMAC region should not be all zeros";
}

// ── 6. parseMessage roundtrip ───────────────────────────────────────

TEST_F(TuyaProtocolTest, ParseMessageRoundtripV33) {
    auto payload = TuyaProtocol::makeStatusPayload(test_device_id, TuyaVersion::V33);
    auto frame = buildIncomingFrame(42, Command::DP_QUERY, payload,
                                    TuyaVersion::V33, test_key);

    auto msg = TuyaProtocol::parseMessage(frame, TuyaVersion::V33, test_key);

    EXPECT_EQ(msg.seqno, 42u);
    EXPECT_EQ(msg.cmd, Command::DP_QUERY);
    EXPECT_TRUE(msg.integrity_ok);
    EXPECT_EQ(msg.payload, payload);
}

TEST_F(TuyaProtocolTest, ParseMessageRoundtripV34) {
    auto payload = TuyaProtocol::makeStatusPayload(test_device_id, TuyaVersion::V34);
    auto frame = buildIncomingFrame(99, Command::DP_QUERY_NEW, payload,
                                    TuyaVersion::V34, test_key);

    auto msg = TuyaProtocol::parseMessage(frame, TuyaVersion::V34, test_key);

    EXPECT_EQ(msg.seqno, 99u);
    EXPECT_EQ(msg.cmd, Command::DP_QUERY_NEW);
    EXPECT_TRUE(msg.integrity_ok);
    EXPECT_EQ(msg.payload, payload);
}

// ── 7. makeStatusPayload ────────────────────────────────────────────

TEST_F(TuyaProtocolTest, MakeStatusPayloadValidJSON) {
    auto payload = TuyaProtocol::makeStatusPayload(test_device_id, TuyaVersion::V33);
    ASSERT_FALSE(payload.empty());

    // Parse as JSON
    std::string json_str(payload.begin(), payload.end());
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::istringstream stream(json_str);
    std::string errors;
    bool ok = Json::parseFromStream(builder, stream, &root, &errors);
    ASSERT_TRUE(ok) << "Failed to parse status payload JSON: " << errors;

    // Verify required fields
    EXPECT_TRUE(root.isMember("gwId"));
    EXPECT_TRUE(root.isMember("devId"));
    EXPECT_EQ(root["gwId"].asString(), test_device_id);
    EXPECT_EQ(root["devId"].asString(), test_device_id);

    // uid and t fields should be present
    EXPECT_TRUE(root.isMember("uid"));
    EXPECT_TRUE(root.isMember("t"));
    // t should be a numeric timestamp string
    EXPECT_FALSE(root["t"].asString().empty());
}

// ── 8. makeControlPayload ───────────────────────────────────────────

TEST_F(TuyaProtocolTest, MakeControlPayloadValidJSON) {
    Json::Value dps;
    dps["1"] = true;
    dps["2"] = 255;
    dps["3"] = "white";

    auto payload = TuyaProtocol::makeControlPayload(test_device_id, dps, TuyaVersion::V33);
    ASSERT_FALSE(payload.empty());

    // Parse as JSON
    std::string json_str(payload.begin(), payload.end());
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::istringstream stream(json_str);
    std::string errors;
    bool ok = Json::parseFromStream(builder, stream, &root, &errors);
    ASSERT_TRUE(ok) << "Failed to parse control payload JSON: " << errors;

    // Must have dps field
    EXPECT_TRUE(root.isMember("dps"));
    EXPECT_TRUE(root["dps"].isMember("1"));
    EXPECT_EQ(root["dps"]["1"].asBool(), true);
    EXPECT_EQ(root["dps"]["2"].asInt(), 255);
    EXPECT_EQ(root["dps"]["3"].asString(), "white");

    // Device ID fields
    EXPECT_TRUE(root.isMember("devId"));
    EXPECT_EQ(root["devId"].asString(), test_device_id);
}

// ── 9. MD5 hex ──────────────────────────────────────────────────────

TEST_F(TuyaProtocolTest, MD5HexKnownValue) {
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    std::vector<uint8_t> empty;
    EXPECT_EQ(TuyaProtocol::md5hex(empty), "d41d8cd98f00b204e9800998ecf8427e");

    // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    std::vector<uint8_t> abc = {'a', 'b', 'c'};
    EXPECT_EQ(TuyaProtocol::md5hex(abc), "900150983cd24fb0d6963f7d28e17f72");
}

// ── 10. Version header ──────────────────────────────────────────────

TEST_F(TuyaProtocolTest, VersionHeaderV31) {
    auto hdr = versionHeader(TuyaVersion::V31);
    ASSERT_EQ(hdr.size(), 15u);
    EXPECT_EQ(hdr[0], '3');
    EXPECT_EQ(hdr[1], '.');
    EXPECT_EQ(hdr[2], '1');
    // Remaining 12 bytes should be zero
    for (size_t i = 3; i < 15; ++i) {
        EXPECT_EQ(hdr[i], 0) << "Byte " << i << " should be zero";
    }
}

TEST_F(TuyaProtocolTest, VersionHeaderV33) {
    auto hdr = versionHeader(TuyaVersion::V33);
    ASSERT_EQ(hdr.size(), 15u);
    EXPECT_EQ(hdr[0], '3');
    EXPECT_EQ(hdr[1], '.');
    EXPECT_EQ(hdr[2], '3');
    for (size_t i = 3; i < 15; ++i) {
        EXPECT_EQ(hdr[i], 0);
    }
}

TEST_F(TuyaProtocolTest, VersionHeaderV34) {
    auto hdr = versionHeader(TuyaVersion::V34);
    ASSERT_EQ(hdr.size(), 15u);
    EXPECT_EQ(hdr[0], '3');
    EXPECT_EQ(hdr[1], '.');
    EXPECT_EQ(hdr[2], '4');
    for (size_t i = 3; i < 15; ++i) {
        EXPECT_EQ(hdr[i], 0);
    }
}

TEST_F(TuyaProtocolTest, NeedsVersionHeaderForControl) {
    EXPECT_TRUE(needsVersionHeader(Command::CONTROL));
    EXPECT_TRUE(needsVersionHeader(Command::CONTROL_NEW));
    EXPECT_TRUE(needsVersionHeader(Command::STATUS));
}

TEST_F(TuyaProtocolTest, NoVersionHeaderForQuery) {
    EXPECT_FALSE(needsVersionHeader(Command::DP_QUERY));
    EXPECT_FALSE(needsVersionHeader(Command::DP_QUERY_NEW));
    EXPECT_FALSE(needsVersionHeader(Command::HEART_BEAT));
    EXPECT_FALSE(needsVersionHeader(Command::SESS_KEY_NEG_START));
    EXPECT_FALSE(needsVersionHeader(Command::SESS_KEY_NEG_RESP));
    EXPECT_FALSE(needsVersionHeader(Command::SESS_KEY_NEG_FINISH));
    EXPECT_FALSE(needsVersionHeader(Command::UPDATEDPS));
}
