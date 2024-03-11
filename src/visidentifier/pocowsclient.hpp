/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef POCO_WS_CLIENT_HPP_
#define POCO_WS_CLIENT_HPP_

#include "visidentifier/wsclient.hpp"
#include "wspendingrequests.hpp"
#include <Poco/Event.h>
#include <Poco/Mutex.h>
#include <Poco/Net/HTTPMessage.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/RunnableAdapter.h>

#include "wsclientevent.hpp"
#include "wspendingrequests.hpp"
#include <atomic>
#include <memory>
#include <mutex>

class PocoWSClient : public WSClientItf {
public:
    /**
     * Creates Web socket client instance.
     *
     * @param config web socket config.
     */
    PocoWSClient(const WSConfig& config);

    /**
     * Connect to Web Socket server
     */
    void Connect() override;

    /**
     * Close Web Socket client
     */
    void Close() override;

    /**
     * Disconnect Web Socket client
     */
    void Disconnect() override;

    /**
     * Generate request id
     *
     * @returns std::string
     */
    std::string GenerateRequestID() override;

    /**
     * Get Event
     *
     * @returns WSClientEvent&
     */
    WSClientEvent& GetEvent() override;

    /**
     * Set message handler
     *
     * @param handler handler functor
     * @returns WSClientEvent&
     */
    void SetMessageHandler(MessageHandlerFunc handler) override;

    /**
     * Send request. Blocks till the response is received or timed-out (WSSendFrameError is thrown)
     *
     * @param requestId request id
     * @param message request payload
     * @returns std::string
     */
    std::string SendRequest(const std::string& requestId, const std::string& message) override;

    /**
     * Send message. Doesn't wait for response.
     *
     * @param message request payload
     */
    void SendMessage(const std::string& message);

    /**
     * Destroys web socket client instance.
     */
    ~PocoWSClient() override;

private:
    void HandleResponse(const std::string& frame);

    void ReceiveFrames();

    void JoinReceiveFramesThread();

    WSConfig                                       mWSConfig;
    Poco::Mutex                                    mMutex;
    bool                                           mIsConnected {false};
    Poco::SharedPtr<Poco::Net::Context>            mCryptoContext;
    std::unique_ptr<Poco::Net::HTTPSClientSession> mClientSession;
    Poco::Net::HTTPRequest                         mHttpRequest;
    Poco::Net::HTTPResponse                        mHttpResponse;
    std::unique_ptr<Poco::Net::WebSocket>          mWebSocket;
    PendingRequests                                mPendingRequests;
    Poco::RunnableAdapter<PocoWSClient>            mReceivedFramesThreadRunnable;
    Poco::Thread                                   mReceivedFramesThread;
    MessageHandlerFunc                             HandleSubscription;
    WSClientEvent                                  mWSClientErrorEvent;
};

#endif
