/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024s EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "logger/logger.hpp"
#include "utils/json.hpp"

using namespace testing;

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

class JsonTest : public Test { };

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

namespace json_utils {

TEST_F(JsonTest, GetValueByKey)
{
    const struct {
        std::string key;
        std::string json;
        std::string expectedResult;
    } test[] = {{"key", "value", "value"}, {"key", R"({"key" : "value"})", "value"},
        {"no-such-key", R"({"key" : "value"})", ""}, {"key", R"({"key" : {"1" : "value"}})", ""}};

    for (auto it = std::begin(test); it != std::end(test); ++it) {
        EXPECT_EQ(GetValueByKey(it->key, it->json), it->expectedResult) << "key: " << it->key << ", json: " << it->json;
    }
}

TEST_F(JsonTest, GetValueArrayByKey)
{
    const auto res = GetValueArrayByKey("key", R"({"key":[0,1,2]})");
    ASSERT_EQ(res.size(), 3);
    EXPECT_EQ(res[0], "0");
    EXPECT_EQ(res[1], "1");
    EXPECT_EQ(res[2], "2");
}

TEST_F(JsonTest, GetValueArrayByKeyEmptyJson)
{
    auto res = GetValueArrayByKey("key", R"({"key":[]})");
    ASSERT_TRUE(res.empty());

    res = GetValueArrayByKey("key", R"({})");
    ASSERT_TRUE(res.empty());

    res = GetValueArrayByKey("key", R"()");
    ASSERT_TRUE(res.empty());
}

TEST_F(JsonTest, GetValueArrayByKeyArrayJson)
{
    const auto res = GetValueArrayByKey("key", R"([1, 2])");
    ASSERT_EQ(res.size(), 2);
    EXPECT_EQ(res[0], "1");
    EXPECT_EQ(res[1], "2");
}

TEST_F(JsonTest, GetValueArrayByKeyInvalidJson)
{
    const auto res = GetValueArrayByKey("key", R"({"test-path"})");
    ASSERT_TRUE(res.empty());
}

TEST_F(JsonTest, GetValueArrayByKeyKeyNotFound)
{
    const auto res = GetValueArrayByKey("not-found-key", R"({"key":"value"})");
    EXPECT_TRUE(res.empty());
}
} // namespace json_utils
