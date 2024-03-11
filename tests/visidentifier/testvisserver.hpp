#pragma once

//
// WebSocketServer.cpp
//
// This sample demonstrates the WebSocket class.
//
// Copyright (c) 2012, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include "Poco/Format.h"
#include "Poco/JSON/Object.h"
#include "Poco/JSON/Parser.h"
#include "Poco/JSON/Stringifier.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/SecureServerSocket.h"
#include "Poco/Net/WebSocket.h"
#include "Poco/Runnable.h"
#include "Poco/Util/ServerApplication.h"
#include "visidentifier/visprotocol.hpp"
#include <iostream>
#include <mutex>

struct VisSubscription {
    std::string id;
    std::string path;
};

class VisParams {
public:
    void Set(const std::string& key, const std::string& value);

    void Set(const std::string& key, const std::vector<std::string>& values);

    std::vector<std::string> Get(const std::string& key);

    void AddSubscription(const std::string& id, const std::string& path);

    void ClearSubscription();

    std::vector<VisSubscription> GetSubscriptions();

    static VisParams& Instance();

private:
    VisParams() = default;

    std::mutex                                      mMutex;
    std::map<std::string, std::vector<std::string>> mMap;

    std::vector<VisSubscription> mVisSubscription;
};

class WebSocketRequestHandler : public Poco::Net::HTTPRequestHandler {
    /// Handle a WebSocket connection.
    std::string handleGetRequest(const std::string& frame);

    std::string handleSubscribeRequest(const std::string& frame);

    std::string handleUnsubscribeAllRequest(const std::string& frame);

    std::string handleFrame(const std::string& frame);

public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;
};

class RequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest&) override;
};

class WebSocketServer {
    Poco::Event stopEvent;

public:
    void start(const std::vector<std::string>& args);

    void stop();
};