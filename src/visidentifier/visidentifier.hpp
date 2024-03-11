/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VISIDENTIFIER_HPP_
#define VISIDENTIFIER_HPP_

#include "visidentifier/wsclient.hpp"
#include <Poco/Event.h>
#include <Poco/Mutex.h>
#include <Poco/RunnableAdapter.h>
#include <Poco/Thread.h>
#include <aos/iam/identhandler.hpp>
#include <map>
#include <string>
#include <vector>

/**
 * VIS Subscriptions.
 */
class VisSubscriptions {
public:
    using HanlderF = std::function<aos::Error(const std::string&)>;

    /**
     * Register subscribtion.
     *
     * @param subscriptionId subscription id.
     * @param subscriptionHandler subscription handler.
     * @return Error.
     */
    void RegisterSubscription(const std::string& subscriptionId, HanlderF&& subscriptionHandler);

    /**
     * Process subscribtion.
     *
     * @param subscriptionId subscription id.
     * @param value subscribtion value.
     * @return Error.
     */
    aos::Error ProcessSubscription(const std::string& subscriptionId, const std::string& value);

private:
    Poco::Mutex                     mMutex;
    std::map<std::string, HanlderF> mSubscriptionMap;
};

/**
 * VIS Identifier.
 */
class VisIdentifier : public aos::iam::identhandler::IdentHandlerItf {
public:
    /**
     * Creates a new object instance.
     */
    VisIdentifier();

    /**
     * Initializes vis identifier.
     *
     * @param wsClientPtr web socket client pointer.
     * @param subjectsObserverPtr subject observer pointer.
     * @param initTimeoutMiliseconds timeout in miliseconds for this method to complete.
     * @return Error.
     */
    aos::Error Init(WSClientItfPtr                                   wsClientPtr,
        std::shared_ptr<aos::iam::identhandler::SubjectsObserverItf> subjectsObserverPtr,
        const long                                                   initTimeoutMiliseconds = 5000);

    /**
     * Returns System ID.
     *
     * @returns RetWithError<StaticString>.
     */
    aos::RetWithError<aos::StaticString<aos::cSystemIDLen>> GetSystemID() override;

    /**
     * Returns unit model.
     *
     * @returns RetWithError<StaticString>.
     */
    aos::RetWithError<aos::StaticString<aos::cUnitModelLen>> GetUnitModel() override;

    /**
     * Returns subjects.
     *
     * @param[out] subjects result subjects.
     * @returns Error.
     */
    aos::Error GetSubjects(aos::Array<aos::StaticString<aos::cSubjectIDLen>>& subjects) override;

    /**
     * Destroys vis identifier object instance.
     */
    ~VisIdentifier();

private:
    void Close();

    void HandleConnection();

    void HandleSubscription(const std::string& message);

    aos::Error HandleSubjectsSubscription(const std::string& value);

    std::string SendGetRequest(const std::string& path);

    void SendUnsubscribeAllRequest();

    void Subscribe(const std::string& path, VisSubscriptions::HanlderF&& callback);

    std::shared_ptr<WSClientItf>                                                    mWsClientPtr;
    std::shared_ptr<aos::iam::identhandler::SubjectsObserverItf>                    mSubjectsObserverPtr;
    VisSubscriptions                                                                mSubscriptions;
    aos::StaticString<aos::cSystemIDLen>                                            mSystemId;
    aos::StaticString<aos::cUnitModelLen>                                           mUnitModel;
    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, aos::cMaxSubjectIDSize> mSubjects;
    Poco::RunnableAdapter<VisIdentifier>                                            mHandleConnectionThreadAdaptor;
    Poco::Thread                                                                    mHandleConnectionThread;
    Poco::Event                                                                     mWSClientIsConnected;
    Poco::Event                                                                     mStopHandleSubjectsChangedThread;
    Poco::Mutex                                                                     mMutex;
};

#endif
