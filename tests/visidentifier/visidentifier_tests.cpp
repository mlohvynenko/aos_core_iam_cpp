/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logger/logger.hpp"
#include "testvisserver.hpp"
#include "visidentifier/pocowsclient.hpp"
#include "visidentifier/visidentifier.hpp"
#include "visidentifier/wsexception.hpp"
#include <future>
#include <gmock/gmock.h>
#include <string_view>

using namespace testing;

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/
namespace {
class SubjectsObserverMock : public aos::iam::identhandler::SubjectsObserverItf {
public:
    MOCK_METHOD(aos::Error, SubjectsChanged, (const aos::Array<aos::StaticString<aos::cSubjectIDLen>>&), (override));
};

} // namespace

class MockWSClientItf : public WSClientItf {
public:
    MOCK_METHOD(void, Connect, (), (override));
    MOCK_METHOD(void, Close, (), (override));
    MOCK_METHOD(void, Disconnect, (), (override));
    MOCK_METHOD(std::string, GenerateRequestID, (), (override));
    MOCK_METHOD(WSClientEvent&, GetEvent, (), (override));
    MOCK_METHOD(void, SetMessageHandler, (MessageHandlerFunc), (override));
    MOCK_METHOD(std::string, SendRequest, (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, SendMessage, (const std::string&), (override));
};

class VisidentifierTest : public Test {
protected:
    const std::string kTestSubscriptionId {"1234-4321"};

    std::shared_ptr<SubjectsObserverMock> mSubjectsObserverMockPtr;
    std::shared_ptr<MockWSClientItf>      mWSClientItfMockPtr;

    void SetUp() override
    {
        mSubjectsObserverMockPtr = std::make_shared<StrictMock<SubjectsObserverMock>>();
        mWSClientItfMockPtr      = std::make_shared<StrictMock<MockWSClientItf>>();
        mVisIdentifierPtr        = std::make_shared<VisIdentifier>();
    }

    WSClientItfPtr                  mWsClientPtr;
    WSClientEvent                   mWSClientEvent;
    WSClientItf::MessageHandlerFunc mSubscriptionHandler;

    // This method is called before any test cases in the test suite
    static void SetUpTestSuite()
    {
        static Logger mLogger;

        mLogger.SetBackend(Logger::Backend::eStdIO);
        mLogger.SetLogLevel(aos::LogLevelEnum::eDebug);
        mLogger.Init();
    }

    void InitSuccessfully()
    {
        EXPECT_CALL(*mWSClientItfMockPtr, SetMessageHandler)
            .Times(1)
            .WillOnce(Invoke([this](WSClientItf::MessageHandlerFunc functor) { mSubscriptionHandler = functor; }));

        EXPECT_CALL(*mWSClientItfMockPtr, Connect).Times(1);
        EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
        EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
            .Times(1)
            .WillOnce(Return(visprotocol::SubscribeResponse("", kTestSubscriptionId).toString()));
        EXPECT_CALL(*mWSClientItfMockPtr, GetEvent).Times(1).WillOnce(ReturnRef(mWSClientEvent));

        const auto err = mVisIdentifierPtr->Init(mWSClientItfMockPtr, mSubjectsObserverMockPtr);
        ASSERT_TRUE(err.IsNone()) << err.Message();
    }

    void StopSuccessfully()
    {
        EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
        EXPECT_CALL(*mWSClientItfMockPtr, SendMessage).Times(1);
        EXPECT_CALL(*mWSClientItfMockPtr, Close).Times(1).WillOnce(Invoke([this] {
            mWSClientEvent.Set(WSClientEvent::EventEnum::CLOSED, "mock closed");
        }));
    }

    std::shared_ptr<VisIdentifier> mVisIdentifierPtr;
};

TEST_F(VisidentifierTest, InitWSClientNotAccessible)
{
    mWSClientItfMockPtr.reset();
    const auto err = mVisIdentifierPtr->Init(mWSClientItfMockPtr, mSubjectsObserverMockPtr);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eInvalidArgument)) << err.Message();
}

TEST_F(VisidentifierTest, InitSubjectsObserverNotAccessible)
{
    mSubjectsObserverMockPtr.reset();
    const auto err = mVisIdentifierPtr->Init(mWSClientItfMockPtr, mSubjectsObserverMockPtr);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eInvalidArgument)) << err.Message();
}

TEST_F(VisidentifierTest, InitSucceeds)
{
    InitSuccessfully();
    StopSuccessfully();
}

TEST_F(VisidentifierTest, InitTimedOut)
{
    EXPECT_CALL(*mWSClientItfMockPtr, SetMessageHandler).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, Connect).WillRepeatedly(Invoke([]() { throw WSConnectionFailed(""); }));

    const auto err = mVisIdentifierPtr->Init(mWSClientItfMockPtr, mSubjectsObserverMockPtr, 1);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eTimeout)) << err.Message();

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, SendMessage).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, Close).Times(1);
    mVisIdentifierPtr.reset();
}

TEST_F(VisidentifierTest, SubscriptionNotificationReceivedAndObserverIsNotified)
{
    InitSuccessfully();

    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, 3> subjects;

    EXPECT_CALL(*mSubjectsObserverMockPtr, SubjectsChanged)
        .Times(1)
        .WillOnce(Invoke([&subjects](const auto& newSubjects) {
            subjects = newSubjects;
            return aos::ErrorEnum::eNone;
        }));

    const std::string kSubscriptionNofiticationJson
        = R"({"action":"subscription","subscriptionId":"1234-4321","value":[11,12,13], "timestamp": 0})";

    mSubscriptionHandler(kSubscriptionNofiticationJson);

    EXPECT_EQ(subjects.Size(), 3);

    // Observer is notified only if subsription json contains new value
    for (size_t i {0}; i < 3; ++i) {
        EXPECT_CALL(*mSubjectsObserverMockPtr, SubjectsChanged).Times(0);
        mSubscriptionHandler(kSubscriptionNofiticationJson);
    }

    StopSuccessfully();
}

TEST_F(VisidentifierTest, SubscriptionNotificationReceivedUnknownSubscriptionId)
{
    InitSuccessfully();

    EXPECT_CALL(*mSubjectsObserverMockPtr, SubjectsChanged).Times(0);

    mSubscriptionHandler(
        R"({"action":"subscription","subscriptionId":"unknown-subscriptionId","value":[11,12,13], "timestamp": 0})");

    StopSuccessfully();
}

TEST_F(VisidentifierTest, SubscriptionNotificationReceivedInvalidPayload)
{
    InitSuccessfully();

    EXPECT_CALL(*mSubjectsObserverMockPtr, SubjectsChanged).Times(0);

    ASSERT_NO_THROW(mSubscriptionHandler(R"({"action"})"));

    StopSuccessfully();
}

TEST_F(VisidentifierTest, SubscriptionNotificationValueExceedsMaxLimit)
{
    InitSuccessfully();

    EXPECT_CALL(*mSubjectsObserverMockPtr, SubjectsChanged).Times(0);

    Poco::JSON::Object notification;
    notification.set("action", "subscription");
    notification.set("timestamp", 0);
    notification.set("subscriptionId", kTestSubscriptionId);
    notification.set("value", std::vector<std::string>(aos::cMaxSubjectIDSize + 1, "test"));

    std::ostringstream jsonStream;
    Poco::JSON::Stringifier::stringify(notification, jsonStream);

    ASSERT_NO_THROW(mSubscriptionHandler(jsonStream.str()));

    StopSuccessfully();
}

TEST_F(VisidentifierTest, ReconnectOnFailSendFrame)
{
    EXPECT_CALL(*mWSClientItfMockPtr, SetMessageHandler).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, Disconnect).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, Connect).Times(2);

    EXPECT_CALL(*mWSClientItfMockPtr, GetEvent).Times(1).WillOnce(ReturnRef(mWSClientEvent));

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(2);
    EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
        .Times(2)
        .WillOnce(Invoke([](const std::string&, const std::string&) -> std::string { throw WSSendFrameError("mock"); }))
        .WillOnce(Return(visprotocol::SubscribeResponse("", kTestSubscriptionId).toString()));

    const auto err = mVisIdentifierPtr->Init(mWSClientItfMockPtr, mSubjectsObserverMockPtr);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    StopSuccessfully();
}

TEST_F(VisidentifierTest, GetSystemIDExceedsMaxSize)
{
    InitSuccessfully();

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
        .WillOnce(Invoke([](const std::string&, const std::string&) -> std::string {
            Poco::JSON::Object response;
            response.set("action", "get");
            response.set("requestId", "requestId");
            response.set("timestamp", 0);
            response.set("value", std::string(aos::cSystemIDLen + 1, '1'));

            std::ostringstream jsonStream;
            Poco::JSON::Stringifier::stringify(response, jsonStream);

            return jsonStream.str();
        }));

    const auto err = mVisIdentifierPtr->GetSystemID();
    EXPECT_TRUE(err.mError.Is(aos::ErrorEnum::eNoMemory)) << err.mError.Message();

    StopSuccessfully();
}

TEST_F(VisidentifierTest, GetSystemIDRequestFailed)
{
    InitSuccessfully();

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
        .WillOnce(
            Invoke([](const std::string&, const std::string&) -> std::string { throw WSSendFrameError("mock"); }));

    const auto err = mVisIdentifierPtr->GetSystemID();
    EXPECT_TRUE(err.mError.Is(aos::ErrorEnum::eFailed)) << err.mError.Message();

    StopSuccessfully();
}

TEST_F(VisidentifierTest, GetUnitModelExceedsMaxSize)
{
    InitSuccessfully();

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
        .WillOnce(Invoke([](const std::string&, const std::string&) -> std::string {
            Poco::JSON::Object response;
            response.set("action", "get");
            response.set("requestId", "requestId");
            response.set("timestamp", 0);
            response.set("value", std::string(aos::cUnitModelLen + 1, '1'));

            std::ostringstream jsonStream;
            Poco::JSON::Stringifier::stringify(response, jsonStream);

            return jsonStream.str();
        }));

    const auto err = mVisIdentifierPtr->GetUnitModel();
    EXPECT_TRUE(err.mError.Is(aos::ErrorEnum::eNoMemory)) << err.mError.Message();

    StopSuccessfully();
}

TEST_F(VisidentifierTest, GetUnitModelRequestFailed)
{
    InitSuccessfully();

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
        .WillOnce(
            Invoke([](const std::string&, const std::string&) -> std::string { throw WSSendFrameError("mock"); }));

    const auto err = mVisIdentifierPtr->GetUnitModel();
    EXPECT_TRUE(err.mError.Is(aos::ErrorEnum::eFailed)) << err.mError.Message();

    StopSuccessfully();
}

TEST_F(VisidentifierTest, GetSubjectsRequestFailed)
{
    InitSuccessfully();

    EXPECT_CALL(*mWSClientItfMockPtr, GenerateRequestID).Times(1);
    EXPECT_CALL(*mWSClientItfMockPtr, SendRequest)
        .WillOnce(
            Invoke([](const std::string&, const std::string&) -> std::string { throw WSSendFrameError("mock"); }));

    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, aos::cMaxSubjectIDSize> subjects;
    const auto err = mVisIdentifierPtr->GetSubjects(subjects);
    EXPECT_TRUE(err.Is(aos::ErrorEnum::eFailed));
    EXPECT_TRUE(subjects.IsEmpty());

    StopSuccessfully();
}
