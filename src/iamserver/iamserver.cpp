/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <fstream>
#include <memory>
#include <numeric>

#include <Poco/Pipe.h>
#include <Poco/PipeStream.h>
#include <Poco/Process.h>
#include <Poco/StreamCopier.h>

#include <aos/common/crypto.hpp>
#include <aos/common/cryptoutils.hpp>
#include <aos/common/tools/string.hpp>
#include <aos/common/types.hpp>
#include <aos/iam/certhandler.hpp>
#include <utils/exception.hpp>
#include <utils/grpchelper.hpp>

#include "iamserver.hpp"
#include "log.hpp"

/***********************************************************************************************************************
 * Statics
 **********************************************************************************************************************/

static const std::string CorrectAddress(const std::string& addr)
{
    if (addr.empty()) {
        throw aos::common::utils::AosException("bad address");
    }

    if (addr[0] == ':') {
        return "0.0.0.0" + addr;
    }

    return addr;
}

static aos::Error ExecProcess(const std::string& cmd, const std::vector<std::string>& args, std::string& output)
{
    Poco::Pipe            outPipe;
    Poco::ProcessHandle   ph = Poco::Process::launch(cmd, args, nullptr, &outPipe, &outPipe);
    Poco::PipeInputStream outStream(outPipe);

    Poco::StreamCopier::copyToString(outStream, output);
    Poco::trimRightInPlace(output);

    int exitCode = ph.wait();

    return exitCode == 0 ? aos::ErrorEnum::eNone : aos::ErrorEnum::eFailed;
}

static aos::Error ExecCommand(const std::string& cmdName, const std::vector<std::string>& cmdArgs)
{
    if (!cmdArgs.empty()) {
        std::string                    output;
        const std::vector<std::string> args {cmdArgs.begin() + 1, cmdArgs.end()};

        auto err = ExecProcess(cmdArgs[0], args, output);
        if (!err.IsNone()) {
            LOG_ERR() << cmdName.c_str() << " exec failed: output = " << output.c_str()
                      << ", err = " << AOS_ERROR_WRAP(err);

            return err;
        }
    }

    return aos::ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

aos::Error IAMServer::Init(const Config& config, aos::iam::certhandler::CertHandlerItf& certHandler,
    aos::iam::identhandler::IdentHandlerItf& identHandler, aos::iam::permhandler::PermHandlerItf& permHandler,
    aos::cryptoutils::CertLoader& certLoader, aos::crypto::x509::ProviderItf& cryptoProvider,
    aos::iam::NodeInfoProviderItf& nodeInfoProvider, aos::iam::nodemanager::NodeManagerItf& nodeManager,
    aos::iam::provisionmanager::ProvisionManagerItf& provisionManager, bool provisioningMode)
{
    LOG_DBG() << "IAM Server init";

    mConfig = config;

    aos::NodeInfo nodeInfo;

    auto err = nodeInfoProvider.GetNodeInfo(nodeInfo);
    if (!err.IsNone()) {
        LOG_ERR() << "Failed to get node info: " << AOS_ERROR_WRAP(err);

        return err;
    }

    err = nodeManager.SetNodeInfo(nodeInfo);
    if (!err.IsNone()) {
        LOG_ERR() << "Failed to set node info: " << AOS_ERROR_WRAP(err);

        return err;
    }

    err = mPublicMessageHandler.Init(
        mNodeController, identHandler, permHandler, nodeInfoProvider, nodeManager, provisionManager);
    if (!err.IsNone()) {
        LOG_ERR() << "Public message handler init error: " << AOS_ERROR_WRAP(err);

        return err;
    }

    err = mProtectedMessageHandler.Init(
        mNodeController, identHandler, permHandler, nodeInfoProvider, nodeManager, provisionManager);
    if (!err.IsNone()) {
        LOG_ERR() << "Protected message handler init error: " << AOS_ERROR_WRAP(err);

        return err;
    }

    try {
        std::shared_ptr<grpc::ServerCredentials> publicOpt, protectedOpt;

        if (!provisioningMode) {
            aos::iam::certhandler::CertInfo certInfo;

            err = certHandler.GetCertificate(aos::String(mConfig.mCertStorage.c_str()), {}, {}, certInfo);
            if (!err.IsNone()) {
                return AOS_ERROR_WRAP(err);
            }

            publicOpt    = aos::common::utils::GetTLSServerCredentials(certInfo, certLoader, cryptoProvider);
            protectedOpt = aos::common::utils::GetMTLSServerCredentials(
                certInfo, mConfig.mCACert.c_str(), certLoader, cryptoProvider);
        } else {
            publicOpt    = grpc::InsecureServerCredentials();
            protectedOpt = grpc::InsecureServerCredentials();
        }

        CreatePublicServer(mConfig.mIAMPublicServerURL, publicOpt);
        CreateProtectedServer(mConfig.mIAMProtectedServerURL, protectedOpt, provisioningMode);
    } catch (const std::exception& e) {
        LOG_ERR() << "IAM Server init error: " << e.what();

        return aos::ErrorEnum::eFailed;
    }

    if (err = nodeManager.SubscribeNodeInfoChange(static_cast<aos::iam::nodemanager::NodeInfoListenerItf&>(*this));
        !err.IsNone()) {
        LOG_ERR() << "Failed to subscribe node info change: " << AOS_ERROR_WRAP(err);

        return AOS_ERROR_WRAP(err);
    }

    return aos::ErrorEnum::eNone;
}

aos::Error IAMServer::OnStartProvisioning(const aos::String& password)
{
    (void)password;

    LOG_DBG() << "Start provisioning callback";

    return ExecCommand("Start provisioning", mConfig.mStartProvisioningCmdArgs);
}

aos::Error IAMServer::OnFinishProvisioning(const aos::String& password)
{
    (void)password;

    LOG_DBG() << "Finish provisioning callback";

    return ExecCommand("Finish provisioning", mConfig.mFinishProvisioningCmdArgs);
}

aos::Error IAMServer::OnDeprovision(const aos::String& password)
{
    (void)password;

    LOG_DBG() << "Deprovision callback";

    return ExecCommand("Deprovision", mConfig.mDeprovisionCmdArgs);
}

aos::Error IAMServer::OnEncryptDisk(const aos::String& password)
{
    (void)password;

    LOG_DBG() << "Encrypt disk callback";

    return ExecCommand("Encrypt disk", mConfig.mDiskEncryptionCmdArgs);
}

void IAMServer::OnNodeInfoChange(const aos::NodeInfo& info)
{
    LOG_DBG() << "Node info change notification";

    mPublicMessageHandler.OnNodeInfoChange(info);
    mProtectedMessageHandler.OnNodeInfoChange(info);
}

void IAMServer::OnNodeRemoved(const aos::String& id)
{
    LOG_DBG() << "Node removed notification";

    mPublicMessageHandler.OnNodeRemoved(id);
    mProtectedMessageHandler.OnNodeRemoved(id);
}

IAMServer::~IAMServer()
{
    LOG_DBG() << "IAM Server shutdown";

    if (mPublicServer) {
        mPublicServer->Shutdown();
        mPublicServer->Wait();
    }

    if (mProtectedServer) {
        mProtectedServer->Shutdown();
        mProtectedServer->Wait();
    }

    mPublicMessageHandler.Close();
    mProtectedMessageHandler.Close();
    mNodeController.Close();
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

aos::Error IAMServer::SubjectsChanged(const aos::Array<aos::StaticString<aos::cSubjectIDLen>>& messages)
{
    const auto err = mPublicMessageHandler.SubjectsChanged(messages);
    if (!err.IsNone()) {
        LOG_ERR() << "Public channel returned subjects changed error: " << err;
    }

    if (auto errProtected = mProtectedMessageHandler.SubjectsChanged(messages); !errProtected.IsNone()) {
        LOG_ERR() << "Protected channel returned subjects changed error: " << err;

        return errProtected;
    }

    return err;
}

void IAMServer::CreatePublicServer(const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials)
{
    grpc::ServerBuilder builder;

    builder.AddListeningPort(CorrectAddress(addr), credentials);

    mPublicMessageHandler.RegisterServices(builder);

    mPublicServer = builder.BuildAndStart();
}

void IAMServer::CreateProtectedServer(
    const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials, bool provisionMode)
{
    grpc::ServerBuilder builder;

    builder.AddListeningPort(CorrectAddress(addr), credentials);

    mProtectedMessageHandler.RegisterServices(builder, provisionMode);

    mProtectedServer = builder.BuildAndStart();
}
