/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VIS_PROTOCOL_HPP_
#define VIS_PROTOCOL_HPP_

#include <Poco/JSON/Object.h>
#include <string>

namespace visprotocol {
constexpr const char* ActionGet            = "get";
constexpr const char* ActionSubscribe      = "subscribe";
constexpr const char* ActionSubscription   = "subscription";
constexpr const char* ActionUnsubscribeAll = "unsubscribeAll";

/*******************************************************************************
 * Types
 ******************************************************************************/

using json_object = Poco::JSON::Object;

// MessageHeader VIS message header.
struct MessageHeader {
    MessageHeader() = default;
    MessageHeader(const std::string& action, const std::string& requestId);
    MessageHeader(Poco::JSON::Object::Ptr pObject);
    MessageHeader(const std::string& json);
    std::string action;
    std::string requestId;
    json_object toJSON() const;
    std::string toString() const;
};

// ErrorInfo VIS error info.
struct ErrorInfo {
    int         number {0};
    std::string reason;
    std::string message;
};

// GetRequest VIS get request.
struct GetRequest {
    GetRequest() = default;
    GetRequest(const MessageHeader& messageHeader, const std::string& path);
    GetRequest(const std::string& json);

    MessageHeader messageHeader;
    std::string   path;
    json_object   toJSON() const;
    std::string   toString() const;
};

// GetResponse VIS get success response.
struct GetResponse {
    GetResponse(const MessageHeader& messageHeader);
    GetResponse(const std::string& json);
    json_object toJSON() const;
    std::string toString() const;

    MessageHeader messageHeader;
    ErrorInfo     error;
    std::string   value;
    int64_t       timestamp {0};
};

// SubscribeRequest VIS subscribe request.
struct SubscribeRequest {
    SubscribeRequest() = default;
    SubscribeRequest(const MessageHeader& messageHeader, const std::string& path, const std::string& filters);
    SubscribeRequest(const std::string& json);
    MessageHeader messageHeader;
    std::string   path;
    std::string   filters;
    json_object   toJSON() const;
    std::string   toString() const;
};

// SubscribeResponse VIS subscribe success response.
struct SubscribeResponse {
    SubscribeResponse(const std::string& requestId, const std::string& subscriptionId);
    SubscribeResponse(const std::string& json);
    json_object toJSON() const;
    std::string toString() const;

    MessageHeader messageHeader;
    ErrorInfo     error;
    std::string   subscriptionId;
    int64_t       timestamp {0};
};

// SubscriptionNotification VIS subscription notification.
struct SubscriptionNotification {
    SubscriptionNotification(const std::string& json);
    ErrorInfo   error;
    std::string action;
    std::string subscriptionId;
    std::string value;
    int64_t     timestamp {0};
};
} // namespace visprotocol

#endif
