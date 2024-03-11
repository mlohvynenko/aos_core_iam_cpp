/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils/json.hpp"

#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>

namespace json_utils {

Poco::Dynamic::Var ParseJson(const std::string& json)
{
    auto parser = Poco::JSON::Parser();
    try {
        return parser.parse(json);
    } catch (const Poco::Exception&) {
    }

    return {};
}

std::string GetValueByKey(const std::string& key, const std::string& jsonStr)
{
    try {
        const auto parseResult = ParseJson(jsonStr);
        if (parseResult.isEmpty())
            return jsonStr;

        Poco::JSON::Object::Ptr pObject = parseResult.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return {};

        if (pObject->has(key) == false) {
            return {};
        }

        if (pObject->get(key).isString() == false) {
            return {};
        }

        return pObject->getValue<std::string>(key);
    } catch (const Poco::Exception&) {
    }

    return jsonStr;
}

std::vector<std::string> GetValueArrayByKey(const std::string& key, const std::string& jsonStr)
{
    try {
        const auto parseResult = ParseJson(jsonStr);

        Poco::JSON::Array::Ptr pathArray;

        if (parseResult.isArray()) {
            pathArray = parseResult.extract<Poco::JSON::Array::Ptr>();
        } else {
            Poco::JSON::Object::Ptr pObject = parseResult.extract<Poco::JSON::Object::Ptr>();
            if (pObject.isNull())
                return {};

            if (pObject->has(key) == false) {
                return {};
            }
            Poco::Dynamic::Var pathVar = pObject->get(key);
            pathArray                  = pathVar.extract<Poco::JSON::Array::Ptr>();
        }

        std::vector<std::string> valueArray;
        valueArray.reserve(pathArray->size());

        for (const auto& i : *pathArray) {
            valueArray.push_back(i.convert<std::string>());
        }

        return valueArray;

    } catch (const Poco::Exception& e) {
        std::cerr << __FUNCTION__ << " " << e.what() << std::endl;
    }

    return {};
}

} // namespace json_utils
