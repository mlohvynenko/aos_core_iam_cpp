/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pocowsclient.hpp"
#include "aos/common/tools/uuid.hpp"
#include "log.hpp"
#include "utils/json.hpp"
#include "utils/scopeexit.hpp"
#include "visprotocol.hpp"
#include "wsexception.hpp"
#include <Poco/JSON/Object.h>
#include <Poco/Net/Context.h>
#include <Poco/URI.h>

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

PocoWSClient::PocoWSClient(const WSConfig& config)
    : mWSConfig(config)
    , mReceivedFramesThreadRunnable(*this, &PocoWSClient::ReceiveFrames)
{
    mHttpRequest.setMethod(Poco::Net::HTTPRequest::HTTP_GET);
    mHttpRequest.setVersion(Poco::Net::HTTPMessage::HTTP_1_1);
}

void PocoWSClient::Connect()
{
    Poco::ScopedLock lk(mMutex);

    if (mIsConnected) {
        return;
    }

    Poco::URI uri(mWSConfig.visServer);
    try {
        JoinReceiveFramesThread();

        Poco::Net::Context::Ptr context = new Poco::Net::Context(
            Poco::Net::Context::TLS_CLIENT_USE, "", mWSConfig.caCertFile, "", Poco::Net::Context::VERIFY_NONE, 9);

        mClientSession = std::make_unique<Poco::Net::HTTPSClientSession>(uri.getHost(), uri.getPort(), context);
        mWebSocket     = std::make_unique<Poco::Net::WebSocket>(*mClientSession, mHttpRequest, mHttpResponse);

        mIsConnected = true;
        mWSClientErrorEvent.Reset();

        mReceivedFramesThread.start(mReceivedFramesThreadRunnable);

        LOG_INF() << "PocoWSClient::Connect succeeded. URI: " << uri.toString().c_str();

    } catch (const std::exception& e) {
        LOG_ERR() << "PocoWSClient::Connect failed. URI: " << uri.toString().c_str() << " with error: " << e.what();

        throw WSConnectionFailed(e.what(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed));
    }
}

void PocoWSClient::Close()
{
    Poco::ScopedLock lk(mMutex);

    LOG_INF() << "Close Web Socket client";

    try {
        if (mIsConnected) {
            mWebSocket->shutdown();
        }

    } catch (const std::exception& e) {
        LOG_ERR() << AosException(e.what(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed)).what();
    }

    mIsConnected = false;
    mWSClientErrorEvent.Set(WSClientEvent::EventEnum::CLOSED, "ws connection has been closed on the client side.");
}

void PocoWSClient::Disconnect()
{
    Poco::ScopedLock lk(mMutex);

    LOG_INF() << "Disconnect Web Socket client";

    if (!mIsConnected) {
        return;
    }

    try {
        mWebSocket->shutdown();
        mWebSocket->close();

    } catch (const std::exception& e) {
        LOG_ERR() << AosException(e.what(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed)).what();
    }

    mIsConnected = false;
}

std::string PocoWSClient::GenerateRequestID()
{
    const auto uuid    = aos::uuid::CreateUUID();
    const auto uuidStr = aos::uuid::UUIDToString(uuid);

    return {uuidStr.begin(), uuidStr.end()};
}

WSClientEvent& PocoWSClient::GetEvent()
{
    return mWSClientErrorEvent;
}

void PocoWSClient::SetMessageHandler(MessageHandlerFunc handler)
{
    HandleSubscription = std::move(handler);
}

std::string PocoWSClient::SendRequest(const std::string& requestId, const std::string& message)
{
    auto requestParams = std::make_shared<RequestParams>(requestId);
    mPendingRequests.Add(requestParams);

    ScopeExit onExit(
        [pendinRequest = &mPendingRequests, id = requestParams->requestId]() { pendinRequest->Remove(id); });

    SendMessage(message);

    LOG_DBG() << "Waiting server response for requestId: " << requestId.c_str();
    if (!requestParams->rspChannel.tryWait(mWSConfig.webSocketTimeoutMiliseconds)) {
        throw WSSendFrameError("", AOS_ERROR_WRAP(aos::ErrorEnum::eTimeout));
    }

    const std::string response = requestParams->response;
    LOG_DBG() << "Got server response for requestId: " << requestId.c_str();

    return response;
}

void PocoWSClient::SendMessage(const std::string& message)
{
    Poco::ScopedLock lk(mMutex);

    if (!mIsConnected) {
        throw WSNoConnectionError("Not connected", AOS_ERROR_WRAP(aos::ErrorEnum::eFailed));
    }

    try {
        mWebSocket->setSendTimeout(Poco::Timespan(mWSConfig.webSocketTimeoutMiliseconds));
        const int len = mWebSocket->sendFrame(message.c_str(), message.length(), Poco::Net::WebSocket::FRAME_TEXT);

        LOG_DBG() << "Sent " << len << " bytes of the message \"" << message.c_str() << "\"";

    } catch (const std::exception& e) {
        mWSClientErrorEvent.Set(WSClientEvent::EventEnum::FAILED, e.what());

        throw WSSendFrameError(e.what(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed));
    }
}

PocoWSClient::~PocoWSClient()
{
    Close();
    JoinReceiveFramesThread();
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

void PocoWSClient::HandleResponse(const std::string& frame)
{
    try {
        const auto              result  = json_utils::ParseJson(frame);
        Poco::JSON::Object::Ptr pObject = result.extract<Poco::JSON::Object::Ptr>();

        if (pObject.isNull()) {
            return;
        }

        const auto action = pObject->get("action");
        if (action == "subscription") {
            HandleSubscription(frame);

            return;
        }

        const auto requestId = pObject->get("requestId").convert<std::string>();
        if (requestId.empty()) {
            throw AosException("invalid requestId tag received");
        }

        if (mPendingRequests.SetResponse(requestId, frame) == false) {
            HandleSubscription(frame);
        }

    } catch (const Poco::Exception& e) {
        LOG_ERR() << AosException(e.what(), AOS_ERROR_WRAP(aos::ErrorEnum::eFailed)).what();
    }
}

void PocoWSClient::ReceiveFrames()
{
    LOG_DBG() << "PocoWSClient::ReceiveFrames has been started.";

    try {
        int flags;
        int n;

        char buffer[1024];

        do {
            n = mWebSocket->receiveFrame(buffer, sizeof(buffer), flags);
            LOG_DBG() << "PocoWSClient::ReceiveFrames recived " << n << " bytes. Flags = " << flags;

            if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
                mWSClientErrorEvent.Set(WSClientEvent::EventEnum::FAILED, "got Close frame from server");

                return;
            }

            if (n > 0) {
                const std::string message(buffer, n);
                HandleResponse(message);
            }

        } while (n > 0);

    } catch (const Poco::Exception& e) {
        LOG_DBG() << AosException(e.what(), AOS_ERROR_WRAP(aos::ErrorEnum::eRuntime)).what();
        mWSClientErrorEvent.Set(WSClientEvent::EventEnum::FAILED, e.what());

        return;
    }

    mWSClientErrorEvent.Set(WSClientEvent::EventEnum::FAILED, "ReceiveFrames stopped");
}

void PocoWSClient::JoinReceiveFramesThread()
{
    if (mReceivedFramesThread.isRunning()) {
        mReceivedFramesThread.join();
    }
}
