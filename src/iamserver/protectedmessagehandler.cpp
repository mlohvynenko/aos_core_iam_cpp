/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <aos/common/crypto.hpp>
#include <aos/common/cryptoutils.hpp>
#include <aos/common/tools/string.hpp>
#include <aos/common/types.hpp>
#include <aos/iam/certhandler.hpp>

#include "log.hpp"
#include "protectedmessagehandler.hpp"

/***********************************************************************************************************************
 * Statics
 **********************************************************************************************************************/

static aos::RetWithError<std::string> ConvertSerialToProto(
    const aos::StaticArray<uint8_t, aos::crypto::cSerialNumSize>& src)
{
    aos::StaticString<aos::crypto::cSerialNumStrLen> result;

    auto err = result.ByteArrayToHex(src);

    return {result.Get(), err};
}

template <size_t Size>
static void ConvertToProto(
    const aos::Array<aos::StaticString<Size>>& src, google::protobuf::RepeatedPtrField<std::string>& dst)
{
    for (const auto& val : src) {
        dst.Add(val.CStr());
    }
}

static common::v1::ErrorInfo ConvertAosErrorToProto(aos::Error error)
{
    common::v1::ErrorInfo result;

    result.set_aos_code(static_cast<int32_t>(error.Value()));
    result.set_exit_code(error.Errno());

    if (!error.IsNone()) {
        aos::StaticString<aos::cErrorMessageLen> message;

        auto err = message.Convert(error);

        result.set_message(err.IsNone() ? message.CStr() : error.Message());
    }

    return result;
}

template <typename Message>
static void SetErrorInfo(Message& message, const aos::Error& error)
{
    *message.mutable_error() = ConvertAosErrorToProto(error);
}

static aos::InstanceIdent ConvertToAOS(const iamproto::InstanceIdent& val)
{
    aos::InstanceIdent result;

    result.mServiceID = val.service_id().c_str();
    result.mSubjectID = val.subject_id().c_str();
    result.mInstance  = val.instance();

    return result;
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

aos::Error ProtectedMessageHandler::Init(NodeController& nodeController,
    aos::iam::identhandler::IdentHandlerItf& identHandler, aos::iam::permhandler::PermHandlerItf& permHandler,
    aos::iam::NodeInfoProviderItf& nodeInfoProvider, aos::iam::nodemanager::NodeManagerItf& nodeManager,
    aos::iam::provisionmanager::ProvisionManagerItf& provisionManager)
{
    return PublicMessageHandler::Init(
        nodeController, identHandler, permHandler, nodeInfoProvider, nodeManager, provisionManager);
}

void ProtectedMessageHandler::RegisterServices(grpc::ServerBuilder& builder, bool provisionMode)
{
    PublicMessageHandler::RegisterServices(builder);

    if (GetPermHandler() != nullptr) {
        builder.RegisterService(static_cast<iamproto::IAMPermissionsService::Service*>(this));
    }

    if (IsMainNode()) {
        builder.RegisterService(static_cast<iamproto::IAMCertificateService::Service*>(this));

        if (provisionMode) {
            builder.RegisterService(static_cast<iamproto::IAMProvisioningService::Service*>(this));
        }

        builder.RegisterService(static_cast<iamproto::IAMNodesService::Service*>(this));
    }
}

void ProtectedMessageHandler::Close()
{
    PublicMessageHandler::Close();
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * IAMPublicNodesService implementation
 **********************************************************************************************************************/

grpc::Status ProtectedMessageHandler::RegisterNode(grpc::ServerContext*                         context,
    grpc::ServerReaderWriter<::iamproto::IAMIncomingMessages, ::iamproto::IAMOutgoingMessages>* stream)
{
    LOG_DBG() << "Register node has been received on the protected channel";

    using aos::NodeStatus;
    using aos::NodeStatusEnum;

    static const std::vector<NodeStatus> allowedStatuses = {NodeStatusEnum::eProvisioned, NodeStatusEnum::ePaused};

    return GetNodeController()->HandleRegisterNodeStream(allowedStatuses, stream, context, GetNodeManager());
}

/***********************************************************************************************************************
 * IAMNodesService implementation
 **********************************************************************************************************************/

grpc::Status ProtectedMessageHandler::PauseNode([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::PauseNodeRequest* request, iamproto::PauseNodeResponse* response)
{
    const auto& nodeID = request->node_id();

    LOG_DBG() << "Process pause node: nodeID=" << nodeID.c_str();

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->PauseNode(request, response, cDefaultTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    if (auto err = SetNodeStatus(aos::NodeStatusEnum::ePaused); !err.IsNone()) {
        SetErrorInfo(*response, err);
    }

    return grpc::Status::OK;
}

grpc::Status ProtectedMessageHandler::ResumeNode([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::ResumeNodeRequest* request, iamproto::ResumeNodeResponse* response)
{
    const auto& nodeID = request->node_id();

    LOG_DBG() << "Process resume node: nodeID=" << nodeID.c_str();

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->ResumeNode(request, response, cDefaultTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    if (auto err = SetNodeStatus(aos::NodeStatusEnum::eProvisioned); !err.IsNone()) {
        SetErrorInfo(*response, err);
    }

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMProvisioningService implementation
 **********************************************************************************************************************/

grpc::Status ProtectedMessageHandler::GetCertTypes([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::GetCertTypesRequest* request, iamproto::CertTypes* response)
{
    const auto& nodeID = request->node_id();

    LOG_DBG() << "Process get cert types: nodeID = " << nodeID.c_str();

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->GetCertTypes(request, response, cDefaultTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    aos::Error                            err;
    aos::iam::provisionmanager::CertTypes certTypes;

    aos::Tie(certTypes, err) = GetProvisionManager()->GetCertTypes();
    if (!err.IsNone()) {
        LOG_ERR() << "Get certificate types error: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get certificate types error");
    }

    ConvertToProto(certTypes, *response->mutable_types());

    return grpc::Status::OK;
}

grpc::Status ProtectedMessageHandler::StartProvisioning([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::StartProvisioningRequest* request, iamproto::StartProvisioningResponse* response)
{
    const auto& nodeID = request->node_id();

    LOG_DBG() << "Process start provisioning request: nodeID=" << nodeID.c_str();

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->StartProvisioning(request, response, cProvisioningTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    if (auto err = GetProvisionManager()->StartProvisioning(request->password().c_str()); !err.IsNone()) {
        LOG_DBG() << "Provision manager failed: " << AOS_ERROR_WRAP(err);

        SetErrorInfo(*response, err);
    }

    return grpc::Status::OK;
}

grpc::Status ProtectedMessageHandler::FinishProvisioning([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::FinishProvisioningRequest* request, iamproto::FinishProvisioningResponse* response)
{
    const auto& nodeID = request->node_id();

    LOG_DBG() << "Process finish provisioning request: nodeID=" << nodeID.c_str();

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->FinishProvisioning(request, response, cProvisioningTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    auto err = GetProvisionManager()->FinishProvisioning(request->password().c_str());
    if (!err.IsNone()) {
        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    if (err = SetNodeStatus(aos::NodeStatusEnum::eProvisioned); !err.IsNone()) {
        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    return grpc::Status::OK;
}

grpc::Status ProtectedMessageHandler::Deprovision([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::DeprovisionRequest* request, iamproto::DeprovisionResponse* response)
{
    const auto& nodeID = request->node_id();

    LOG_DBG() << "Process deprovision request: nodeID=" << nodeID.c_str();

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->Deprovision(request, response, cProvisioningTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    if (auto err = GetProvisionManager()->Deprovision(request->password().c_str()); !err.IsNone()) {
        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    if (auto err = SetNodeStatus(aos::NodeStatusEnum::eUnprovisioned); !err.IsNone()) {
        SetErrorInfo(*response, err);
    }

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMCertificateService implementation
 **********************************************************************************************************************/

grpc::Status ProtectedMessageHandler::CreateKey([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::CreateKeyRequest* request, iamproto::CreateKeyResponse* response)
{
    const auto nodeID   = request->node_id();
    const auto certType = aos::String(request->type().c_str());

    LOG_DBG() << "Process create key request: nodeID=" << nodeID.c_str() << ", type=" << certType;

    aos::StaticString<aos::cSystemIDLen> subject = request->subject().c_str();

    if (subject.IsEmpty() && !GetIdentHandler()) {
        LOG_ERR() << "Subject can't be empty";

        aos::Error err = aos::ErrorEnum::eFailed;
        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    aos::Error err = aos::ErrorEnum::eNone;

    if (subject.IsEmpty() && GetIdentHandler()) {
        Tie(subject, err) = GetIdentHandler()->GetSystemID();
        if (!err.IsNone()) {
            LOG_ERR() << "Getting system ID error: " << AOS_ERROR_WRAP(err);

            SetErrorInfo(*response, err);

            return grpc::Status::OK;
        }
    }

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            iamproto::CreateKeyRequest keyRequest = *request;
            keyRequest.set_subject(subject.CStr());

            return handler->CreateKey(&keyRequest, response, cDefaultTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    const auto password = aos::String(request->password().c_str());

    aos::StaticString<aos::crypto::cCSRPEMLen> csr;

    if (err = GetProvisionManager()->CreateKey(certType, subject, password, csr); !err.IsNone()) {
        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    response->set_node_id(nodeID);
    response->set_type(certType.CStr());
    response->set_csr(csr.CStr());

    return grpc::Status::OK;
}

grpc::Status ProtectedMessageHandler::ApplyCert([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::ApplyCertRequest* request, iamproto::ApplyCertResponse* response)
{
    const auto nodeID   = request->node_id();
    const auto certType = aos::String(request->type().c_str());

    LOG_DBG() << "Process apply cert request: nodeID=" << nodeID.c_str() << ",type=" << certType;

    response->set_node_id(nodeID);
    response->set_type(certType.CStr());

    if (!ProcessOnThisNode(nodeID)) {
        if (auto handler = GetNodeController()->GetNodeStreamHandler(nodeID); handler) {
            return handler->ApplyCert(request, response, cDefaultTimeout);
        }

        return grpc::Status(grpc::StatusCode::INTERNAL, "node stream handler not found");
    }

    const auto pemCert = aos::String(request->cert().c_str());

    LOG_DBG() << "Process apply cert request: type=" << certType << ", nodeID=" << nodeID.c_str();

    aos::iam::certhandler::CertInfo certInfo;

    if (auto err = GetProvisionManager()->ApplyCert(certType, pemCert, certInfo); !err.IsNone()) {
        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    aos::Error  err;
    std::string serial;

    Tie(serial, err) = ConvertSerialToProto(certInfo.mSerial);
    if (!err.IsNone()) {
        LOG_ERR() << "Serial conversion problem: " << AOS_ERROR_WRAP(err);

        SetErrorInfo(*response, err);

        return grpc::Status::OK;
    }

    response->set_cert_url(certInfo.mCertURL.CStr());
    response->set_serial(serial);

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPermissionsService implementation
 **********************************************************************************************************************/

grpc::Status ProtectedMessageHandler::RegisterInstance([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::RegisterInstanceRequest* request, iamproto::RegisterInstanceResponse* response)
{
    aos::Error err         = aos::ErrorEnum::eNone;
    const auto aosInstance = ConvertToAOS(request->instance());

    LOG_DBG() << "Process register instance: serviceID=" << aosInstance.mServiceID
              << ", subjectID=" << aosInstance.mSubjectID << ", instance=" << aosInstance.mInstance;

    // Convert permissions
    aos::StaticArray<aos::iam::permhandler::FunctionalServicePermissions, aos::cMaxNumServices> aosPermissions;

    for (const auto& [service, permissions] : request->permissions()) {
        err = aosPermissions.PushBack({});
        if (!err.IsNone()) {
            LOG_ERR() << "Error allocating permissions: " << AOS_ERROR_WRAP(err);

            return grpc::Status(grpc::StatusCode::INTERNAL, "Permissions allocation problem");
        }

        aos::iam::permhandler::FunctionalServicePermissions& servicePerm = aosPermissions.Back().mValue;
        servicePerm.mName                                                = service.c_str();

        for (const auto& [key, val] : permissions.permissions()) {
            if (err = servicePerm.mPermissions.PushBack({key.c_str(), val.c_str()}); !err.IsNone()) {
                LOG_ERR() << "Error allocating permissions: " << AOS_ERROR_WRAP(err);

                return grpc::Status(grpc::StatusCode::INTERNAL, "Permissions allocation problem");
            }
        }
    }

    aos::StaticString<aos::uuid::cUUIDLen> secret;

    Tie(secret, err) = GetPermHandler()->RegisterInstance(aosInstance, aosPermissions);

    if (!err.IsNone()) {
        LOG_ERR() << "Register instance error: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Register instance error");
    }

    response->set_secret(secret.CStr());

    return grpc::Status::OK;
}

grpc::Status ProtectedMessageHandler::UnregisterInstance([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::UnregisterInstanceRequest* request, [[maybe_unused]] google::protobuf::Empty* response)
{
    const auto instance = ConvertToAOS(request->instance());

    LOG_DBG() << "Process unregister instance: serviceID=" << instance.mServiceID
              << ", subjectID=" << instance.mSubjectID << ", instance=" << instance.mInstance;

    if (auto err = GetPermHandler()->UnregisterInstance(instance); !err.IsNone()) {
        LOG_ERR() << "Unregister instance error: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Unregister instance error");
    }

    return grpc::Status::OK;
}

bool ProtectedMessageHandler::ProcessOnThisNode(const std::string& nodeId)
{
    return nodeId.empty() || aos::String(nodeId.c_str()) == GetNodeInfo().mID;
}
