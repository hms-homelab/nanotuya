// Tests for TuyaCloud region mapping. Only built when cloud support is on
// (-DBUILD_WITH_CLOUD=ON), which defines NANOTUYA_HAS_CLOUD.
#include <gtest/gtest.h>

#ifdef NANOTUYA_HAS_CLOUD
#include "nanotuya/TuyaCloud.h"

using nanotuya::TuyaCloud;

TEST(TuyaCloudRegion, KnownRegionsMapToDatacenters) {
    EXPECT_EQ(TuyaCloud::regionBaseUrl("us"), "https://openapi.tuyaus.com");
    EXPECT_EQ(TuyaCloud::regionBaseUrl("eu"), "https://openapi.tuyaeu.com");
    EXPECT_EQ(TuyaCloud::regionBaseUrl("cn"), "https://openapi.tuyacn.com");
    EXPECT_EQ(TuyaCloud::regionBaseUrl("in"), "https://openapi.tuyain.com");
    EXPECT_EQ(TuyaCloud::regionBaseUrl("sg"), "https://openapi.tuyasg.com");
}

TEST(TuyaCloudRegion, UnknownRegionFallsBackToUs) {
    EXPECT_EQ(TuyaCloud::regionBaseUrl(""), "https://openapi.tuyaus.com");
    EXPECT_EQ(TuyaCloud::regionBaseUrl("xx"), "https://openapi.tuyaus.com");
    EXPECT_EQ(TuyaCloud::regionBaseUrl("US"), "https://openapi.tuyaus.com");
}
#endif  // NANOTUYA_HAS_CLOUD
