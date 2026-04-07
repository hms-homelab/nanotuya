#pragma once
#include <json/json.h>
#include <string>
#include <vector>

namespace nanotuya {

/// Tuya Cloud OpenAPI client for device discovery and cloud control.
/// Authenticates via HMAC-SHA256 signed requests.
/// Requires: API key + secret from Tuya IoT Platform (https://iot.tuya.com).
class TuyaCloud {
public:
    /// @param api_key    Client ID from Tuya IoT Platform
    /// @param api_secret Client Secret from Tuya IoT Platform
    /// @param region     API region: "us", "eu", "cn", "in"
    TuyaCloud(const std::string& api_key, const std::string& api_secret,
              const std::string& region = "us");

    /// Discover all devices linked to this Tuya account.
    /// Returns JSON array of device objects with local keys:
    /// [{id, name, key, mac, category, product_name, online, ...}]
    Json::Value discoverDevices();

    /// Get status of a single device from cloud.
    Json::Value getDeviceStatus(const std::string& device_id);

    /// Send command via cloud API.
    /// @param commands JSON: {"commands": [{"code":"switch_led","value":true}]}
    bool sendCommand(const std::string& device_id, const Json::Value& commands);

    /// Get last error message.
    std::string lastError() const { return last_error_; }

private:
    /// Get or refresh access token (cached, auto-refreshes on expiry).
    bool ensureAccessToken();

    /// Make signed GET request to Tuya OpenAPI.
    Json::Value apiGet(const std::string& path);

    /// Make signed POST request to Tuya OpenAPI.
    Json::Value apiPost(const std::string& path, const Json::Value& body);

    /// Generate HMAC-SHA256 signature for Tuya API request.
    /// StringToSign = client_id + access_token + t + method + URL + body_hash
    std::string generateSign(const std::string& method, const std::string& path,
                             const std::string& body, long timestamp);

    /// Perform HTTP request with libcurl.
    std::string httpRequest(const std::string& method, const std::string& url,
                            const std::string& body,
                            const std::vector<std::string>& headers);

    std::string api_key_;
    std::string api_secret_;
    std::string base_url_;
    std::string access_token_;
    long token_expiry_ = 0;
    std::string last_error_;
};

} // namespace nanotuya
