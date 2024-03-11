#include "testvisserver.hpp"

#include "visidentifier/visprotocol.hpp"
#include <Poco/Format.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Net/AcceptCertificateHandler.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/Runnable.h>
#include <Poco/Util/ServerApplication.h>
#include <iostream>

void VisParams::Set(const std::string& key, const std::string& value)
{
    std::lock_guard lk(mMutex);
    mMap[key] = {value};
}

void VisParams::Set(const std::string& key, const std::vector<std::string>& values)
{
    std::lock_guard lk(mMutex);
    mMap[key] = values;
}

std::vector<std::string> VisParams::Get(const std::string& key)
{
    std::lock_guard lk(mMutex);
    if (const auto it = mMap.find(key); it != mMap.end()) {
        return it->second;
    }

    throw std::runtime_error("key not found");
}

void VisParams::AddSubscription(const std::string& id, const std::string& path)
{
    std::lock_guard lk(mMutex);
    mVisSubscription.push_back({id, path});
}

void VisParams::ClearSubscription()
{
    std::lock_guard lk(mMutex);
    mVisSubscription.clear();
}

std::vector<VisSubscription> VisParams::GetSubscriptions()
{
    std::lock_guard lk(mMutex);
    return mVisSubscription;
}

VisParams& VisParams::Instance()
{
    static VisParams instance;
    return instance;
}

/// Handle a WebSocket connection.
std::string WebSocketRequestHandler::handleGetRequest(const std::string& frame)
{
    const visprotocol::GetRequest getRequest(frame);
    visprotocol::GetResponse      getResponse(getRequest.messageHeader);

    Poco::JSON::Object valueJsonObj;
    const auto&        path = getRequest.path;

    Poco::JSON::Array valueArray;
    for (const auto& value : VisParams::Instance().Get(path)) {
        valueArray.add(value);
    }

    if (valueArray.size() > 1) {
        valueJsonObj.set(path, valueArray);
    } else {
        valueJsonObj.set(path, valueArray.empty() ? "" : valueArray.begin()->extract<std::string>());
    }

    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(valueJsonObj, jsonStream);

    getResponse.value = jsonStream.str();

    return getResponse.toString();
}

std::string WebSocketRequestHandler::handleSubscribeRequest(const std::string& frame)
{
    const visprotocol::SubscribeRequest subscribeRequest(frame);
    static uint32_t                     lastSubscribeId {0};

    const visprotocol::SubscribeResponse subscribeResponse(
        subscribeRequest.messageHeader.requestId, std::to_string(lastSubscribeId++));

    VisParams::Instance().AddSubscription(subscribeResponse.subscriptionId, subscribeRequest.path);

    return subscribeResponse.toString();
}

std::string WebSocketRequestHandler::handleUnsubscribeAllRequest(const std::string& frame)
{
    VisParams::Instance().ClearSubscription();
    return frame;
}

std::string WebSocketRequestHandler::handleFrame(const std::string& frame)
{
    const visprotocol::MessageHeader messageHeader(frame);
    if (messageHeader.action == visprotocol::ActionGet) {
        return handleGetRequest(frame);
    } else if (messageHeader.action == visprotocol::ActionSubscribe) {
        return handleSubscribeRequest(frame);
    } else if (messageHeader.action == visprotocol::ActionUnsubscribeAll) {
        return handleUnsubscribeAllRequest(frame);
    }

    return frame;
}

void WebSocketRequestHandler::handleRequest(
    Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response)
{
    try {
        Poco::Net::WebSocket ws(request, response);
        std::cout << "WebSocket connection established." << std::endl;
        int flags;
        int n;
        do {
            char buffer[1024] = {'\0'};
            n                 = ws.receiveFrame(buffer, sizeof(buffer), flags);
            if (n == 0) {
                continue;
            } else if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
                ws.sendFrame(nullptr, 0, flags);
                break;
            }

            const std::string frameStr(buffer);
            std::cout << Poco::format("Frame received (val=%s, length=%d, flags=0x%x).", frameStr, n, unsigned(flags))
                      << std::endl;

            const auto responseFrame = handleFrame(frameStr);
            ws.sendFrame(responseFrame.c_str(), responseFrame.length(), flags);
        } while (n > 0 && (flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) != Poco::Net::WebSocket::FRAME_OP_CLOSE);
        std::cout << "WebSocket connection closed." << std::endl;
    } catch (const Poco::Net::WebSocketException& exc) {
        std::cerr << "handle request caught WebSocketException: " << exc.what() << std::endl;

        switch (exc.code()) {
        case Poco::Net::WebSocket::WS_ERR_HANDSHAKE_UNSUPPORTED_VERSION:
            response.set("Sec-WebSocket-Version", Poco::Net::WebSocket::WEBSOCKET_VERSION);
            // fallthrough
        case Poco::Net::WebSocket::WS_ERR_NO_HANDSHAKE:
        case Poco::Net::WebSocket::WS_ERR_HANDSHAKE_NO_VERSION:
        case Poco::Net::WebSocket::WS_ERR_HANDSHAKE_NO_KEY:
            response.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            response.setContentLength(0);
            response.send();
            break;
        }
    }
}

Poco::Net::HTTPRequestHandler* RequestHandlerFactory::createRequestHandler(const Poco::Net::HTTPServerRequest&)
{
    return new WebSocketRequestHandler;
}

void WebSocketServer::start(const std::vector<std::string>& args)
{
    Poco::Net::initializeSSL();

    Poco::SharedPtr<Poco::Net::AcceptCertificateHandler> pCert = new Poco::Net::AcceptCertificateHandler(false);
    Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::SERVER_USE, args[0], args[1], "",
        Poco::Net::Context::VERIFY_NONE, 9, false, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

    Poco::Net::SSLManager::instance().initializeClient(0, pCert, pContext);

    const unsigned short          port = std::stoul(args[2]);
    Poco::Net::SecureServerSocket svs(port, 64, pContext);
    Poco::Net::HTTPServer         srv(new RequestHandlerFactory, svs, new Poco::Net::HTTPServerParams);
    srv.start();

    stopEvent.wait();
    srv.stop();
}

void WebSocketServer::stop()
{
    stopEvent.set();
}
