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

static std::unique_ptr<std::thread>     VisServerThread;
static std::unique_ptr<WebSocketServer> VisServer;

static void InitVisServer()
{
    static const std::vector<std::string> kVisServerArgs {"/apps/vis/private.pem", "/apps/vis/server.pem", "4566"};

    VisServer       = std::make_unique<WebSocketServer>();
    VisServerThread = std::make_unique<std::thread>([] { VisServer->start(kVisServerArgs); });

    std::this_thread::sleep_for(std::chrono::seconds(3));
}

static void StopVisServer()
{
    // Stop the server application by sending a termination request
    if (VisServer)
        VisServer->stop();

    // Wait for the server thread to finish
    if (VisServerThread->joinable())
        VisServerThread->join();

    VisServer.reset();
}

class PocoWSClientTests : public Test {
protected:
    static const WSConfig mConfig;

    void SetUp() override { ASSERT_NO_THROW(mWsClientPtr = std::make_shared<PocoWSClient>(mConfig)); }

    std::shared_ptr<PocoWSClient> mWsClientPtr;

    // This method is called before any test cases in the test suite
    static void SetUpTestSuite()
    {
        static Logger mLogger;

        mLogger.SetBackend(Logger::Backend::eStdIO);
        mLogger.SetLogLevel(aos::LogLevelEnum::eDebug);
        mLogger.Init();

        InitVisServer();
    }

    static void TearDownTestSuite() { StopVisServer(); }
};

const WSConfig PocoWSClientTests::mConfig {"wss://localhost:4566", "/apps/vis/server.pem", 10000};

TEST_F(PocoWSClientTests, Connect)
{
    ASSERT_NO_THROW(mWsClientPtr->Connect());
    ASSERT_NO_THROW(mWsClientPtr->Connect());
}

TEST_F(PocoWSClientTests, Close)
{
    ASSERT_NO_THROW(mWsClientPtr->Connect());
    ASSERT_NO_THROW(mWsClientPtr->Close());
    ASSERT_NO_THROW(mWsClientPtr->Close());
}

TEST_F(PocoWSClientTests, Disconnect)
{
    ASSERT_NO_THROW(mWsClientPtr->Disconnect());

    ASSERT_NO_THROW(mWsClientPtr->Connect());
    ASSERT_NO_THROW(mWsClientPtr->Disconnect());
}

TEST_F(PocoWSClientTests, GenerateRequestID)
{
    std::string requestId;
    ASSERT_NO_THROW(requestId = mWsClientPtr->GenerateRequestID());
    ASSERT_FALSE(requestId.empty());
}

TEST_F(PocoWSClientTests, SendMessageSucceeds)
{
    ASSERT_NO_THROW(mWsClientPtr->Connect());
    ASSERT_NO_THROW(mWsClientPtr->SendMessage("test"));
}

TEST_F(PocoWSClientTests, SendMessageNotConnected)
{
    try {
        mWsClientPtr->SendMessage("test");
    } catch (const WSNoConnectionError& e) {
        EXPECT_EQ(e.GetError(), aos::ErrorEnum::eFailed);
    } catch (...) {
        FAIL() << "WSNoConnectionError expected";
    }
}

TEST_F(PocoWSClientTests, SendMessageFails)
{
    mWsClientPtr->Connect();

    TearDownTestSuite();

    try {
        mWsClientPtr->SendMessage("test");
    } catch (const WSSendFrameError& e) {
        EXPECT_EQ(e.GetError(), aos::ErrorEnum::eFailed);
    } catch (...) {
        FAIL() << "WSNoConnectionError expected";
    }

    SetUpTestSuite();
}

namespace {
class SubjectsObserverMock : public aos::iam::identhandler::SubjectsObserverItf {
public:
    MOCK_METHOD(aos::Error, SubjectsChanged, (const aos::Array<aos::StaticString<aos::cSubjectIDLen>>&), (override));
};
} // namespace

TEST_F(PocoWSClientTests, VisidentifierGetSystemID)
{
    VisIdentifier visIdentifier;
    auto          observerPtr = std::make_shared<SubjectsObserverMock>();

    auto err = visIdentifier.Init(mWsClientPtr, observerPtr);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    const std::string expectedSystemId {"test-system-id"};
    VisParams::Instance().Set("Attribute.Vehicle.VehicleIdentification.VIN", expectedSystemId);

    const auto systemId = visIdentifier.GetSystemID();
    EXPECT_TRUE(systemId.mError.IsNone()) << systemId.mError.Message();
    EXPECT_EQ(systemId.mValue, expectedSystemId.c_str());
}

TEST_F(PocoWSClientTests, VisidentifierGetUnitModel)
{
    VisIdentifier visIdentifier;
    auto          observerPtr = std::make_shared<SubjectsObserverMock>();

    auto err = visIdentifier.Init(mWsClientPtr, observerPtr);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    const std::string expectedUnitModel {"test-unit-model"};
    VisParams::Instance().Set("Attribute.Aos.UnitModel", expectedUnitModel);

    const auto unitModel = visIdentifier.GetUnitModel();
    EXPECT_TRUE(unitModel.mError.IsNone()) << unitModel.mError.Message();
    EXPECT_EQ(unitModel.mValue, expectedUnitModel.c_str());
}

TEST_F(PocoWSClientTests, VisidentifierGetSubjects)
{
    VisIdentifier visIdentifier;
    auto          observerPtr = std::make_shared<SubjectsObserverMock>();

    auto err = visIdentifier.Init(mWsClientPtr, observerPtr);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    const std::vector<std::string> testSubjects {"1", "2", "3"};
    VisParams::Instance().Set("Attribute.Aos.Subjects", testSubjects);
    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, 3> expectedSubjects;

    for (const auto& testSubject : testSubjects) {
        expectedSubjects.PushBack(testSubject.c_str());
    }

    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, 3> receivedSubjects;

    err = visIdentifier.GetSubjects(receivedSubjects);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    ASSERT_EQ(receivedSubjects, expectedSubjects);
}
