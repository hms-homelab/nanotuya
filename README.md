# nanotuya

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-%23FFDD00.svg?logo=buy-me-a-coffee)](https://www.buymeacoffee.com/aamat09)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

C++ library for the Tuya WiFi local protocol. Query status, set values, and control any Tuya WiFi device over the local network. Minimal dependencies: OpenSSL + jsoncpp.

## Features

- Tuya local protocol v3.1, v3.3, v3.4 (port 6668)
- AES-128-ECB encryption with local key
- v3.4 session key negotiation (3-step HMAC-SHA256 handshake)
- Frame building, parsing, and integrity verification (CRC32 / HMAC-SHA256)
- Fresh TCP connection per operation (proven reliability pattern)
- Zero service dependencies -- just a library

## Supported Devices

Any Tuya WiFi device that uses the local protocol on port 6668:

- Smart bulbs (RGBW, color temp, brightness)
- Smart switches / breakers
- Smart plugs
- Any device with Tuya DPS (Data Points)

## Quick Start

```cpp
#include <nanotuya/TuyaDevice.h>
#include <iostream>

int main() {
    nanotuya::DeviceConfig cfg;
    cfg.id = "your_device_id";
    cfg.ip = "192.168.1.100";
    cfg.local_key = "your_16char_key!";
    cfg.version = nanotuya::TuyaVersion::V33;

    nanotuya::TuyaDevice device(cfg);

    // Query status
    auto status = device.queryStatus();
    if (status) {
        std::cout << "DPS 1 (switch): " << (*status)["1"].asBool() << "\n";
    }

    // Turn on
    device.setValue("1", Json::Value(true));

    // Turn off
    device.setValue("1", Json::Value(false));

    return 0;
}
```

## Getting Credentials

You need the device ID and local key from the Tuya cloud. The easiest way is [tinytuya](https://github.com/jasonacox/tinytuya):

```bash
pip install tinytuya
python -m tinytuya wizard
```

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_EXAMPLES` | OFF | Build the `query_device` CLI tool |
| `BUILD_TESTS` | OFF | Build unit tests (requires GTest) |

### Dependencies

- OpenSSL (libssl-dev)
- jsoncpp (libjsoncpp-dev)
- GTest (libgtest-dev) -- tests only

### Example: Query a Device

```bash
cmake .. -DBUILD_EXAMPLES=ON
make -j$(nproc)
./query_device 192.168.1.100 your_device_id your_local_key 3.3
```

## Use in Your Project

### CMake FetchContent (recommended)

```cmake
include(FetchContent)
FetchContent_Declare(nanotuya
    GIT_REPOSITORY https://github.com/hms-homelab/nanotuya.git
    GIT_TAG v1.0.0
)
FetchContent_MakeAvailable(nanotuya)

target_link_libraries(your_target nanotuya)
```

### Local path with FetchContent fallback

```cmake
# Use local copy if available, fetch from GitHub otherwise
set(NANOTUYA_LOCAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../nanotuya")
if(EXISTS "${NANOTUYA_LOCAL_PATH}/CMakeLists.txt")
    add_subdirectory(${NANOTUYA_LOCAL_PATH} nanotuya)
else()
    include(FetchContent)
    FetchContent_Declare(nanotuya
        GIT_REPOSITORY https://github.com/hms-homelab/nanotuya.git
        GIT_TAG v1.0.0
    )
    FetchContent_MakeAvailable(nanotuya)
endif()
```

### System install

```bash
sudo make install  # installs to /usr/local/lib + /usr/local/include
```

## Protocol Support

| Version | Encryption | Integrity | Status |
|---------|-----------|-----------|--------|
| v3.1 | AES-ECB (CONTROL only) | CRC32 | Supported |
| v3.3 | AES-ECB (all commands) | CRC32 | Supported, tested |
| v3.4 | AES-ECB + session key | HMAC-SHA256 | Supported |
| v3.5 | AES-GCM | GCM tag | Planned |

## DPS Reference

Common Tuya Data Points:

**Bulbs (category "dj"):**
| DP | Name | Type | Range |
|----|------|------|-------|
| 1 | switch_led | bool | on/off |
| 2 | work_mode | string | "white" / "colour" |
| 3 | bright_value | int | 25-255 |
| 4 | temp_value | int | 0-255 |
| 5 | colour_data | hex string | HHHHSSSSBBBB |

**Switches / Breakers (category "tdq"):**
| DP | Name | Type | Range |
|----|------|------|-------|
| 1 | switch | bool | on/off |
| 9 | countdown | int | seconds |

## Related Projects

- [hms-esp-tuya-ble](https://github.com/hms-homelab/hms-esp-tuya-ble) -- ESP32-C3 BLE-to-MQTT bridge for Tuya BLE devices
- [tinytuya](https://github.com/jasonacox/tinytuya) -- Python library (nanotuya is the C++ equivalent)

## License

MIT License -- see [LICENSE](LICENSE) for details.
