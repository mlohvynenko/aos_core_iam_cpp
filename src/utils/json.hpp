/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef JSON_UTILS_HPP_
#define JSON_UTILS_HPP_

#include <Poco/Dynamic/Var.h>

#include <string>
#include <vector>

namespace json_utils {
/**
 * Parse json string
 *
 * @param json json string.
 * @return Poco::Dynamic::Var.
 */
Poco::Dynamic::Var ParseJson(const std::string& json);

/**
 * Get value of the json
 *
 * @param key json key.
 * @param jsonStr json string.
 * @return std::string.
 */
std::string GetValueByKey(const std::string& key, const std::string& jsonStr);

/**
 * Get value of the json
 *
 * @param key json key.
 * @param jsonStr json string.
 * @return std::vector<std::string>.
 */
std::vector<std::string> GetValueArrayByKey(const std::string& key, const std::string& jsonStr);
} // namespace json_utils

#endif
