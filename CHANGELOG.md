# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-04-16

### Fixed
- v3.4 CONTROL_NEW payload missing `devId`, `uid`, `t` in `data` block — devices silently dropped commands
- sendReceive skipping STATUS/UPDATEDPS responses to control commands — v3.4 switches reply with status frames, not control ACKs
- macOS CI: jsoncpp linking via pkg-config IMPORTED_TARGET (resolves "library not found" on Homebrew)

## [1.2.0] - 2026-04-15

### Added
- Persistent connection API: `connect()`, `disconnect()`, `isConnected()`, `heartbeat()`
- `ensureConnected()` for transparent connect-on-demand
- CI workflow (GitHub Actions): build + test on Linux and macOS

### Fixed
- v3.4 session negotiation double-decryption bug (parseMessage already decrypts)

## [1.1.0] - 2026-04-07

### Added
- TuyaCloud API client for device discovery (requires libcurl)
- `BUILD_WITH_CLOUD` CMake option

## [1.0.0] - 2026-04-05

### Added
- Initial release
- Tuya local protocol v3.1, v3.3, v3.4
- AES-128-ECB encryption with PKCS7 padding
- CRC32 integrity (v3.1/v3.3), HMAC-SHA256 (v3.4)
- v3.4 session key negotiation (3-step HMAC handshake)
- JSON payload generators for status query and control
- 51 unit tests
