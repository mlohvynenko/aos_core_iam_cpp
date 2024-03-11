/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "visprotocol.hpp"
#include "utils/json.hpp"
#include "wsexception.hpp"
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>

namespace visprotocol {

MessageHeader::MessageHeader(const std::string& action, const std::string& requestId)
    : action(action)
    , requestId(requestId)
{
}

MessageHeader::MessageHeader(const std::string& json)
{

    try {
        const auto              result  = json_utils::ParseJson(json);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return;

        action    = pObject->getValue<std::string>("action");
        requestId = pObject->getValue<std::string>("requestId");
    } catch (const Poco::Exception& e) {
    }
}

MessageHeader::MessageHeader(Poco::JSON::Object::Ptr pObject)
{
    try {
        if (pObject.isNull())
            return;

        action    = pObject->getValue<std::string>("action");
        requestId = pObject->getValue<std::string>("requestId");
    } catch (const Poco::Exception& e) {
    }
}

json_object MessageHeader::toJSON() const
{
    json_object json;

    json.set("action", action);
    json.set("requestId", requestId);

    return json;
}

std::string MessageHeader::toString() const
{
    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(toJSON(), jsonStream);

    return jsonStream.str();
}

GetRequest::GetRequest(const MessageHeader& messageHeader, const std::string& path)
    : messageHeader(messageHeader)
    , path(path)
{
}

GetRequest::GetRequest(const std::string& json)
{

    try {
        const auto              result  = json_utils::ParseJson(json);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return;

        messageHeader = MessageHeader(pObject);
        path          = pObject->getValue<std::string>("path");
    } catch (const Poco::Exception& e) {
    }
}

json_object SubscribeRequest::toJSON() const
{
    auto json = messageHeader.toJSON();
    json.set("path", path);

    if (filters.empty() == false) { }
    return json;
}

GetResponse::GetResponse(const MessageHeader& messageHeader)
    : messageHeader(messageHeader)
{
}

GetResponse::GetResponse(const std::string& json)
{

    try {
        const auto              result  = json_utils::ParseJson(json);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return;

        messageHeader = MessageHeader(pObject);
        value         = pObject->getValue<std::string>("value");
        timestamp     = pObject->getValue<int64_t>("timestamp");
    } catch (const Poco::Exception& e) {
    }
}

json_object GetResponse::toJSON() const
{
    auto json = messageHeader.toJSON();
    json.set("value", value);

    return json;
}

std::string GetResponse::toString() const
{
    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(toJSON(), jsonStream);

    return jsonStream.str();
}

std::string SubscribeRequest::toString() const
{
    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(toJSON(), jsonStream);

    return jsonStream.str();
}

json_object GetRequest::toJSON() const
{
    auto json = messageHeader.toJSON();
    json.set("path", path);

    return json;
}

std::string GetRequest::toString() const
{
    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(toJSON(), jsonStream);

    return jsonStream.str();
}

SubscribeRequest::SubscribeRequest(
    const MessageHeader& messageHeader, const std::string& path, const std::string& filters)
    : messageHeader(messageHeader)
    , path(path)
    , filters(filters)
{
}

SubscribeRequest::SubscribeRequest(const std::string& json)
{

    try {
        const auto              result  = json_utils::ParseJson(json);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return;

        messageHeader = MessageHeader(pObject);
        path          = pObject->get("path").convert<std::string>();
    } catch (const Poco::Exception& e) {
    }
}

SubscribeResponse::SubscribeResponse(const std::string& requestId, const std::string& subscriptionId)
    : messageHeader(ActionSubscribe, requestId)
    , subscriptionId(subscriptionId)
{
}

SubscribeResponse::SubscribeResponse(const std::string& json)
{

    try {
        const auto              result  = json_utils::ParseJson(json);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return;

        messageHeader  = MessageHeader(pObject);
        subscriptionId = pObject->getValue<std::string>("subscriptionId");
    } catch (const Poco::Exception& e) {
        throw AosException(e.message(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed));
    }
}

json_object SubscribeResponse::toJSON() const
{
    auto json = messageHeader.toJSON();
    json.set("subscriptionId", subscriptionId);
    json.set("timestamp", timestamp);

    return json;
}

std::string SubscribeResponse::toString() const
{
    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(toJSON(), jsonStream);

    return jsonStream.str();
}

SubscriptionNotification::SubscriptionNotification(const std::string& json)
{

    try {
        const auto              result  = json_utils::ParseJson(json);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();
        if (pObject.isNull())
            return;

        action         = pObject->getValue<std::string>("action");
        subscriptionId = pObject->getValue<std::string>("subscriptionId");
        value          = pObject->getValue<std::string>("value");
        timestamp      = pObject->getValue<int64_t>("timestamp");
    } catch (const Poco::Exception& e) {
        throw AosException(e.message(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed));
    }
}

} // namespace visprotocol
