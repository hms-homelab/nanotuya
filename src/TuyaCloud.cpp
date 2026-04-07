#include "nanotuya/TuyaCloud.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <curl/curl.h>

#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace nanotuya {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string sha256hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    for (unsigned int i = 0; i < len; ++i)
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return ss.str();
}

static std::string hmacSHA256(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         result, &len);

    return std::string(reinterpret_cast<char*>(result), len);
}

static std::string toUpperHex(const std::string& raw) {
    std::ostringstream ss;
    for (unsigned char c : raw)
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)c;
    return ss.str();
}

static long nowMillis() {
    return static_cast<long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

static size_t curlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buf = static_cast<std::string*>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

static Json::Value parseJson(const std::string& text) {
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::istringstream stream(text);
    std::string errs;
    Json::parseFromStream(builder, stream, &root, &errs);
    return root;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

TuyaCloud::TuyaCloud(const std::string& api_key, const std::string& api_secret,
                     const std::string& region)
    : api_key_(api_key), api_secret_(api_secret) {

    if (region == "eu")
        base_url_ = "https://openapi.tuyaeu.com";
    else if (region == "cn")
        base_url_ = "https://openapi.tuyacn.com";
    else if (region == "in")
        base_url_ = "https://openapi.tuyain.com";
    else
        base_url_ = "https://openapi.tuyaus.com";
}

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

bool TuyaCloud::ensureAccessToken() {
    if (!access_token_.empty() && nowMillis() < token_expiry_)
        return true;

    // Clear token so generateSign omits it for token request.
    access_token_.clear();

    std::string path = "/v1.0/token?grant_type=1";
    Json::Value resp = apiGet(path);
    if (!resp["success"].asBool()) {
        last_error_ = "Token request failed: " + resp["msg"].asString();
        return false;
    }

    access_token_ = resp["result"]["access_token"].asString();
    int expire_time = resp["result"]["expire_time"].asInt(); // seconds
    token_expiry_ = nowMillis() + (expire_time - 60) * 1000L; // refresh 60s early
    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

Json::Value TuyaCloud::discoverDevices() {
    if (!ensureAccessToken())
        return Json::Value(Json::arrayValue);

    Json::Value all_devices(Json::arrayValue);
    int page_no = 1;
    const int page_size = 100;

    while (true) {
        std::string path = "/v1.0/iot-03/devices?page_no=" + std::to_string(page_no) +
                           "&page_size=" + std::to_string(page_size);
        Json::Value resp = apiGet(path);
        if (!resp["success"].asBool()) {
            last_error_ = "discoverDevices failed: " + resp["msg"].asString();
            break;
        }

        const Json::Value& list = resp["result"]["list"];
        int total = resp["result"]["total"].asInt();

        for (const auto& dev : list) {
            Json::Value d;
            d["id"]           = dev["id"];
            d["name"]         = dev["name"];
            d["key"]          = dev["local_key"];
            d["mac"]          = dev["mac"];
            d["category"]     = dev["category"];
            d["product_name"] = dev["product_name"];
            d["online"]       = dev["online"];
            all_devices.append(d);
        }

        if (static_cast<int>(all_devices.size()) >= total)
            break;
        ++page_no;
    }

    return all_devices;
}

Json::Value TuyaCloud::getDeviceStatus(const std::string& device_id) {
    if (!ensureAccessToken())
        return Json::Value();

    std::string path = "/v1.0/iot-03/devices/" + device_id + "/status";
    Json::Value resp = apiGet(path);
    if (!resp["success"].asBool()) {
        last_error_ = "getDeviceStatus failed: " + resp["msg"].asString();
        return Json::Value();
    }
    return resp["result"];
}

bool TuyaCloud::sendCommand(const std::string& device_id, const Json::Value& commands) {
    if (!ensureAccessToken())
        return false;

    std::string path = "/v1.0/iot-03/devices/" + device_id + "/commands";
    Json::Value resp = apiPost(path, commands);
    if (!resp["success"].asBool()) {
        last_error_ = "sendCommand failed: " + resp["msg"].asString();
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Signed HTTP helpers
// ---------------------------------------------------------------------------

Json::Value TuyaCloud::apiGet(const std::string& path) {
    long ts = nowMillis();
    std::string sign = generateSign("GET", path, "", ts);

    std::vector<std::string> headers;
    headers.push_back("client_id: " + api_key_);
    headers.push_back("sign: " + sign);
    headers.push_back("t: " + std::to_string(ts));
    headers.push_back("sign_method: HMAC-SHA256");
    if (!access_token_.empty())
        headers.push_back("access_token: " + access_token_);

    std::string url = base_url_ + path;
    std::string body = httpRequest("GET", url, "", headers);
    return parseJson(body);
}

Json::Value TuyaCloud::apiPost(const std::string& path, const Json::Value& body) {
    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    std::string body_str = Json::writeString(wb, body);

    long ts = nowMillis();
    std::string sign = generateSign("POST", path, body_str, ts);

    std::vector<std::string> headers;
    headers.push_back("client_id: " + api_key_);
    headers.push_back("sign: " + sign);
    headers.push_back("t: " + std::to_string(ts));
    headers.push_back("sign_method: HMAC-SHA256");
    headers.push_back("Content-Type: application/json");
    if (!access_token_.empty())
        headers.push_back("access_token: " + access_token_);

    std::string url = base_url_ + path;
    std::string resp = httpRequest("POST", url, body_str, headers);
    return parseJson(resp);
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

std::string TuyaCloud::generateSign(const std::string& method, const std::string& path,
                                    const std::string& body, long timestamp) {
    // 1. SHA-256 of body (empty string for GET)
    std::string body_hash = sha256hex(body);

    // 2. stringToSign = METHOD\nbody_hash\n\npath
    std::string stringToSign = method + "\n" + body_hash + "\n\n" + path;

    // 3. signStr = client_id [+ access_token] + t + stringToSign
    std::string signStr = api_key_;
    if (!access_token_.empty())
        signStr += access_token_;
    signStr += std::to_string(timestamp) + stringToSign;

    // 4. HMAC-SHA256 -> uppercase hex
    std::string hmac = hmacSHA256(api_secret_, signStr);
    return toUpperHex(hmac);
}

// ---------------------------------------------------------------------------
// HTTP (libcurl)
// ---------------------------------------------------------------------------

std::string TuyaCloud::httpRequest(const std::string& method, const std::string& url,
                                   const std::string& body,
                                   const std::vector<std::string>& headers) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        last_error_ = "curl_easy_init failed";
        return "{}";
    }

    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }

    struct curl_slist* header_list = nullptr;
    for (const auto& h : headers)
        header_list = curl_slist_append(header_list, h.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        last_error_ = std::string("curl error: ") + curl_easy_strerror(res);
        response = "{}";
    }

    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);

    return response;
}

} // namespace nanotuya
