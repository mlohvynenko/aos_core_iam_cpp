/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "visidentifier.hpp"
#include "log.hpp"
#include "utils/json.hpp"
#include "visprotocol.hpp"
#include "wsexception.hpp"
#include <chrono>

static constexpr const char* vinVISPath = "Attribute.Vehicle.VehicleIdentification.VIN";

static constexpr const char* unitModelPath = "Attribute.Aos.UnitModel";

static constexpr const char* subjectsVISPath = "Attribute.Aos.Subjects";

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

void VisSubscriptions::RegisterSubscription(const std::string& subscriptionId, HanlderF&& subscriptionHandler)
{
    Poco::ScopedLock lk(mMutex);

    LOG_DBG() << "Registred subscription id = " << subscriptionId.c_str();
    mSubscriptionMap[subscriptionId] = std::move(subscriptionHandler);
}

aos::Error VisSubscriptions::ProcessSubscription(const std::string& subscriptionId, const std::string& value)
{
    Poco::ScopedLock lk(mMutex);

    const auto it = mSubscriptionMap.find(subscriptionId);

    if (it == mSubscriptionMap.cend()) {
        LOG_ERR() << "Unexpected subscription id: = " << subscriptionId.c_str();

        return aos::Error::Enum::eNotFound;
    }

    return it->second(value);
}

VisIdentifier::VisIdentifier()
    : mHandleConnectionThreadAdaptor(*this, &VisIdentifier::HandleConnection)
    , mWSClientIsConnected {Poco::Event::EventType::EVENT_MANUALRESET}
    , mStopHandleSubjectsChangedThread {Poco::Event::EventType::EVENT_AUTORESET}

{
}

aos::Error VisIdentifier::Init(WSClientItfPtr                    wsClientPtr,
    std::shared_ptr<aos::iam::identhandler::SubjectsObserverItf> subjectsObserverPtr, const long initTimeoutMiliseconds)
{
    if (wsClientPtr == nullptr || subjectsObserverPtr == nullptr) {
        return aos::ErrorEnum::eInvalidArgument;
    }

    Poco::ScopedLock lk(mMutex);
    mWsClientPtr         = std::move(wsClientPtr);
    mSubjectsObserverPtr = std::move(subjectsObserverPtr);

    mWsClientPtr->SetMessageHandler(std::bind(&VisIdentifier::HandleSubscription, this, std::placeholders::_1));

    mWSClientIsConnected.reset();
    mHandleConnectionThread.start(mHandleConnectionThreadAdaptor);

    return mWSClientIsConnected.tryWait(initTimeoutMiliseconds) ? aos::ErrorEnum::eNone : aos::ErrorEnum::eTimeout;
}

aos::RetWithError<aos::StaticString<aos::cSystemIDLen>> VisIdentifier::GetSystemID()
{
    Poco::ScopedLock lk(mMutex);

    if (mSystemId.IsEmpty()) {
        try {
            const visprotocol::GetResponse response(SendGetRequest(vinVISPath));
            const auto                     systemId = json_utils::GetValueByKey(vinVISPath, response.value);

            if (systemId.size() > mSystemId.MaxSize()) {
                return {{}, aos::ErrorEnum::eNoMemory};
            }

            mSystemId = systemId.c_str();
        } catch (const AosException& e) {
            LOG_ERR() << e.what();

            return {{}, e.GetError()};
        }
    }

    return mSystemId;
}

aos::RetWithError<aos::StaticString<aos::cUnitModelLen>> VisIdentifier::GetUnitModel()
{
    Poco::ScopedLock lk(mMutex);

    if (mUnitModel.IsEmpty()) {
        try {
            const visprotocol::GetResponse response(SendGetRequest(unitModelPath));
            const auto                     unitModel = json_utils::GetValueByKey(unitModelPath, response.value);

            if (unitModel.size() > mUnitModel.MaxSize()) {
                return {{}, aos::ErrorEnum::eNoMemory};
            }

            mUnitModel = unitModel.c_str();
        } catch (const AosException& e) {
            LOG_ERR() << e.what();

            return {{}, e.GetError()};
        }
    }

    return mUnitModel;
}

aos::Error VisIdentifier::GetSubjects(aos::Array<aos::StaticString<aos::cSubjectIDLen>>& subjects)
{
    Poco::ScopedLock lk(mMutex);

    if (mSubjects.IsEmpty()) {
        try {
            const visprotocol::GetResponse response(SendGetRequest(subjectsVISPath));
            const auto responseSubjects = json_utils::GetValueArrayByKey(subjectsVISPath, response.value);

            if (responseSubjects.size() > mSubjects.MaxSize()) {
                return aos::ErrorEnum::eNoMemory;
            }

            for (const auto& subject : responseSubjects) {
                mSubjects.PushBack(subject.c_str());
            }
        } catch (const AosException& e) {
            LOG_ERR() << e.what();

            return e.GetError();
        }
    }

    if (mSubjects.Size() > subjects.MaxSize()) {
        return aos::Error::Enum::eNoMemory;
    }

    subjects = mSubjects;

    return aos::Error::Enum::eNone;
}

VisIdentifier::~VisIdentifier()
{
    if (mWsClientPtr) {
        Close();
    }
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/
void VisIdentifier::Close()
{
    try {
        SendUnsubscribeAllRequest();

        mStopHandleSubjectsChangedThread.set();
        mWsClientPtr->Close();

        if (mHandleConnectionThread.isRunning()) {
            mHandleConnectionThread.join();
        }

        mWSClientIsConnected.reset();

        LOG_INF() << "VisIdentifier has been stopped.";

    } catch (const AosException& e) {
        LOG_ERR() << e.what();
    }
}

void VisIdentifier::HandleConnection()
{
    while (mStopHandleSubjectsChangedThread.tryWait(2000) == false) {
        try {
            mWsClientPtr->Connect();

            Subscribe(
                subjectsVISPath, std::bind(&VisIdentifier::HandleSubjectsSubscription, this, std::placeholders::_1));

            mSystemId.Clear();
            mUnitModel.Clear();
            mSubjects.Clear();

            mWSClientIsConnected.set();

            // block on Wait
            const auto wsClientEvent = mWsClientPtr->GetEvent().Wait();

            if (wsClientEvent.first == WSClientEvent::EventEnum::CLOSED) {
                LOG_INF() << "WS Client connection has been closed. Stopping Vis Identifier Handle Connection thread";

                return;
            }

            mWSClientIsConnected.reset();
            mWsClientPtr->Disconnect();

        } catch (const WSConnectionFailed& e) {
            LOG_ERR() << "WS Connection failed: " << e.message().c_str();

            mWSClientIsConnected.reset();
        } catch (const WSSendFrameError& e) {
            LOG_ERR() << "WS failed to send a frame: " << e.message().c_str();

            mWSClientIsConnected.reset();
            mWsClientPtr->Disconnect();
        } catch (const AosException& e) {
            LOG_ERR() << "Caught AosExcepton: " << e.message().c_str();
        } catch (const std::exception& e) {
            LOG_ERR() << "HandleConnection caught std::exception exception: " << e.what();
        }
    }
}

void VisIdentifier::HandleSubscription(const std::string& message)
{
    try {
        const visprotocol::SubscriptionNotification notification(message);

        if (notification.subscriptionId.empty() || notification.action.empty()) {
            return;
        }

        if (notification.action != visprotocol::ActionSubscription) {
            LOG_ERR() << "Unexpected message received. Action: " << notification.action.c_str();

            return;
        }

        const auto err = mSubscriptions.ProcessSubscription(notification.subscriptionId, notification.value);
        if (err.IsNone() == false) {
            LOG_ERR() << "Failed to process subscription: " << notification.subscriptionId.c_str();
        }
    } catch (const AosException& e) {
        LOG_ERR() << e.message().c_str();
    }
}

aos::Error VisIdentifier::HandleSubjectsSubscription(const std::string& value)
{
    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, aos::cMaxSubjectIDSize> newSubjects;

    const auto responseSubjects = json_utils::GetValueArrayByKey(subjectsVISPath, value);
    if (responseSubjects.size() > newSubjects.MaxSize()) {
        return aos::Error::Enum::eNoMemory;
    }

    for (const auto& subject : responseSubjects) {
        newSubjects.PushBack(subject.c_str());
    }

    Poco::ScopedLock lk(mMutex);
    if (mSubjects != newSubjects) {
        mSubjects = std::move(newSubjects);
        mSubjectsObserverPtr->SubjectsChanged(mSubjects);
    }

    return aos::Error::Enum::eNone;
}

std::string VisIdentifier::SendGetRequest(const std::string& path)
{
    const auto requestId = mWsClientPtr->GenerateRequestID();

    using namespace visprotocol;
    const auto getRequest = GetRequest {MessageHeader {ActionGet, requestId}, path};

    mWSClientIsConnected.wait();
    return mWsClientPtr->SendRequest(requestId, getRequest.toString());
}

void VisIdentifier::SendUnsubscribeAllRequest()
{
    try {
        const visprotocol::MessageHeader unsubscribeAll(
            visprotocol::ActionUnsubscribeAll, mWsClientPtr->GenerateRequestID());

        mWsClientPtr->SendMessage(unsubscribeAll.toString());

    } catch (const AosException& e) {
        LOG_ERR() << e.what();
    }
}

void VisIdentifier::Subscribe(const std::string& path, VisSubscriptions::HanlderF&& callback)
{
    const auto requestId = mWsClientPtr->GenerateRequestID();

    using namespace visprotocol;
    const auto subscribeRequest = SubscribeRequest {MessageHeader {ActionSubscribe, requestId}, path, std::string()};

    const SubscribeResponse subscribeResponse(mWsClientPtr->SendRequest(requestId, subscribeRequest.toString()));

    mSubscriptions.RegisterSubscription(subscribeResponse.subscriptionId, std::move(callback));
}
