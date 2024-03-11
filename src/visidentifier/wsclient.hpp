/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WS_CLIENT_HPP_
#define WS_CLIENT_HPP_

#include "wsclientevent.hpp"
#include <functional>
#include <memory>
#include <string>

/**
 * Web socket configuration.
 */
struct WSConfig {
    std::string visServer;
    std::string caCertFile;
    long        webSocketTimeoutMiliseconds {10000};
};

/**
 * Web socket client interface.
 */
class WSClientItf {
public:
    using MessageHandlerFunc = std::function<void(const std::string&)>;

    /**
     * Connect to Web Socket server
     */
    virtual void Connect() = 0;

    /**
     * Close Web Socket client
     */
    virtual void Close() = 0;

    /**
     * Disconnect Web Socket client
     */
    virtual void Disconnect() = 0;

    /**
     * Generate request id
     *
     * @returns std::string
     */
    virtual std::string GenerateRequestID() = 0;

    /**
     * Get Event
     *
     * @returns WSClientEvent&
     */
    virtual WSClientEvent& GetEvent() = 0;

    /**
     * Set message handler
     *
     * @param handler handler functor
     * @returns WSClientEvent&
     */
    virtual void SetMessageHandler(MessageHandlerFunc handler) = 0;

    /**
     * Send request. Blocks till the response is received or timed-out (WSSendFrameError is thrown)
     *
     * @param requestId request id
     * @param message request payload
     * @returns std::string
     */
    virtual std::string SendRequest(const std::string& requestId, const std::string& message) = 0;

    /**
     * Send message. Doesn't wait for response.
     *
     * @param message request payload
     */
    virtual void SendMessage(const std::string& message) = 0;

    /**
     * Destroys web socket client instance.
     */
    virtual ~WSClientItf() = default;
};

using WSClientItfPtr = std::shared_ptr<WSClientItf>;

#endif
