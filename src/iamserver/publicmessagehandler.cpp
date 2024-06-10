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
#include "publicmessagehandler.hpp"

/***********************************************************************************************************************
 * Statics
 **********************************************************************************************************************/

static const aos::Array<uint8_t> ConvertByteArrayToAos(const std::string& arr)
{
    return {reinterpret_cast<const uint8_t*>(arr.c_str()), arr.length()};
}

template <size_t Size>
static void ConvertToProto(
    const aos::Array<aos::StaticString<Size>>& src, google::protobuf::RepeatedPtrField<std::string>& dst)
{
    for (const auto& val : src) {
        dst.Add(val.CStr());
    }
}

static void ConvertToProto(const aos::Array<aos::StaticString<aos::cSubjectIDLen>>& src, iamproto::Subjects& dst)
{
    dst.clear_subjects();

    for (const auto& subject : src) {
        dst.add_subjects(subject.CStr());
    }
}

static void ConvertToProto(const aos::NodeAttribute& src, iamproto::NodeAttribute& dst)
{
    dst.set_name(src.mName.CStr());
    dst.set_value(src.mValue.CStr());
}

static void ConvertToProto(const aos::PartitionInfo& src, iamproto::PartitionInfo& dst)
{
    dst.set_name(src.mName.CStr());
    dst.set_total_size(src.mTotalSize);

    for (const auto& type : src.mTypes) {
        dst.add_types(type.CStr());
    }
}

static void ConvertToProto(const aos::CPUInfo& src, iamproto::CPUInfo& dst)
{
    dst.set_model_name(src.mModelName.CStr());
    dst.set_num_cores(src.mNumCores);
    dst.set_num_threads(src.mNumThreads);
    dst.set_arch(src.mArch.CStr());
    dst.set_arch_family(src.mArchFamily.CStr());
}

static void ConvertToProto(const aos::NodeInfo& src, iamproto::NodeInfo& dst)
{
    dst.set_id(src.mID.CStr());
    dst.set_type(src.mType.CStr());
    dst.set_name(src.mName.CStr());
    dst.set_status(src.mStatus.ToString().CStr());
    dst.set_os_type(src.mOSType.CStr());
    dst.set_max_dmips(src.mMaxDMIPS);
    dst.set_total_ram(src.mTotalRAM);

    for (const auto& attr : src.mAttrs) {
        ConvertToProto(attr, *dst.add_attrs());
    }

    for (const auto& partition : src.mPartitions) {
        ConvertToProto(partition, *dst.add_partitions());
    }

    for (const auto& cpuInfo : src.mCPUs) {
        ConvertToProto(cpuInfo, *dst.add_cpus());
    }
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

aos::Error PublicMessageHandler::Init(NodeController& nodeController,
    aos::iam::identhandler::IdentHandlerItf& identHandler, aos::iam::permhandler::PermHandlerItf& permHandler,
    aos::iam::NodeInfoProviderItf& nodeInfoProvider, aos::iam::nodemanager::NodeManagerItf& nodeManager,
    aos::iam::provisionmanager::ProvisionManagerItf& provisionManager)
{
    mNodeController   = &nodeController;
    mIdentHandler     = &identHandler;
    mPermHandler      = &permHandler;
    mNodeInfoProvider = &nodeInfoProvider;
    mNodeManager      = &nodeManager;
    mProvisionManager = &provisionManager;

    if (auto err = mNodeInfoProvider->GetNodeInfo(mNodeInfo); !err.IsNone()) {
        LOG_ERR() << "Failed to get node info: " << AOS_ERROR_WRAP(err);

        return AOS_ERROR_WRAP(err);
    }

    return aos::ErrorEnum::eNone;
}

void PublicMessageHandler::RegisterServices(grpc::ServerBuilder& builder)
{
    builder.RegisterService(static_cast<iamanager::IAMVersionService::Service*>(this));
    builder.RegisterService(static_cast<iamproto::IAMPublicService::Service*>(this));

    if (GetPermHandler() != nullptr) {
        builder.RegisterService(static_cast<iamproto::IAMPublicPermissionsService::Service*>(this));
    }

    if (IsMainNode()) {
        if (GetIdentHandler() != nullptr) {
            builder.RegisterService(static_cast<iamproto::IAMPublicIdentityService::Service*>(this));
        }

        builder.RegisterService(static_cast<iamproto::IAMPublicNodesService::Service*>(this));
    }
}

void PublicMessageHandler::OnNodeInfoChange(const aos::NodeInfo& info)
{
    LOG_DBG() << "On node info changed: ID = " << info.mID;

    iamproto::NodeInfo nodeInfo;
    ConvertToProto(info, nodeInfo);

    mNodeChangedController.WriteToSteams(nodeInfo);
}

void PublicMessageHandler::OnNodeRemoved(const aos::String& id)
{
    LOG_DBG() << "On node removed: ID = " << id;
}

aos::Error PublicMessageHandler::SubjectsChanged(const aos::Array<aos::StaticString<aos::cSubjectIDLen>>& messages)
{
    LOG_DBG() << "Subjects changed: count = " << messages.Size();

    iamproto::Subjects subjects;
    ConvertToProto(messages, subjects);

    mSubjectsChangedController.WriteToSteams(subjects);

    return aos::ErrorEnum::eNone;
}

void PublicMessageHandler::Close()
{
    LOG_DBG() << "Close public message handler";

    mNodeChangedController.Close();
    mSubjectsChangedController.Close();
}

/***********************************************************************************************************************
 * Protected
 **********************************************************************************************************************/

bool PublicMessageHandler::IsMainNode() const
{
    // Case-insensitive equality for strings
    auto caseInsensitiveEqual = [](std::string_view a, std::string_view b) {
        return std::equal(
            a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return std::tolower(a) == std::tolower(b); });
    };

    auto it = std::find_if(mNodeInfo.mAttrs.begin(), mNodeInfo.mAttrs.end(), [&](const auto& attr) {
        return caseInsensitiveEqual(std::string_view(attr.mName.CStr(), attr.mName.Size()), cNodeTypeTag);
    });

    if (it != mNodeInfo.mAttrs.end()) {
        return caseInsensitiveEqual(std::string_view(it->mValue.CStr(), it->mValue.Size()), cNodeTypeTagMainNodeValue);
    }

    // If attribute is not found, then it is the main node.
    return true;
}

aos::Error PublicMessageHandler::SetNodeStatus(const aos::NodeStatus& status)
{
    auto err = mNodeInfoProvider->SetNodeStatus(status);
    if (!err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    err = mNodeManager->SetNodeStatus(mNodeInfo.mID, status);
    if (!err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return aos::ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * IAMVersionService implementation
 **********************************************************************************************************************/

grpc::Status PublicMessageHandler::GetAPIVersion([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, iamanager::APIVersion* response)
{
    LOG_DBG() << "Public message handler. Process get API version";

    response->set_version(cIamAPIVersion);

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPublicService implementation
 **********************************************************************************************************************/

grpc::Status PublicMessageHandler::GetNodeInfo([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, iamproto::NodeInfo* response)
{
    LOG_DBG() << "Public message handler. Process get node info";

    ConvertToProto(mNodeInfo, *response);

    return grpc::Status::OK;
}

grpc::Status PublicMessageHandler::GetCert([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::GetCertRequest* request, iamproto::GetCertResponse* response)
{
    LOG_DBG() << "Public message handler. Process get cert request: type=" << request->type().c_str()
              << ", serial=" << request->serial().c_str();

    response->set_type(request->type());

    auto issuer = ConvertByteArrayToAos(request->issuer());

    aos::StaticArray<uint8_t, aos::crypto::cSerialNumSize> serial;

    auto err = aos::String(request->serial().c_str()).HexToByteArray(serial);
    if (!err.IsNone()) {
        LOG_ERR() << "Serial conversion failed: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Serial conversion failed");
    }

    aos::iam::certhandler::CertInfo certInfo;

    err = GetProvisionManager()->GetCert(request->type().c_str(), issuer, serial, certInfo);
    if (!err.IsNone()) {
        LOG_ERR() << "Get certificate error: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get certificate error");
    }

    response->set_key_url(certInfo.mKeyURL.CStr());
    response->set_cert_url(certInfo.mCertURL.CStr());

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPublicIdentityService implementation
 **********************************************************************************************************************/

grpc::Status PublicMessageHandler::GetSystemInfo([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, iamproto::SystemInfo* response)
{
    LOG_DBG() << "Public message handler. Process get system info";

    auto [systemID, err1] = GetIdentHandler()->GetSystemID();

    if (!err1.IsNone()) {
        LOG_DBG() << "Get system ID error: " << err1;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get system ID error");
    }

    auto [boardModel, err2] = GetIdentHandler()->GetUnitModel();
    if (!err2.IsNone()) {
        LOG_DBG() << "Get board model error: " << err2;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get board model error");
    }

    response->set_system_id(systemID.CStr());
    response->set_unit_model(boardModel.CStr());

    return grpc::Status::OK;
}

grpc::Status PublicMessageHandler::GetSubjects([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, iamproto::Subjects* response)
{
    LOG_DBG() << "Public message handler. Process get subjects";

    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, aos::cMaxSubjectIDSize> subjects;

    auto err = GetIdentHandler()->GetSubjects(subjects);
    if (!err.IsNone()) {
        LOG_DBG() << "Get subjects error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get subjects error");
    }

    for (const auto& subj : subjects) {
        response->add_subjects(subj.CStr());
    }

    return grpc::Status::OK;
}

grpc::Status PublicMessageHandler::SubscribeSubjectsChanged([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, grpc::ServerWriter<iamproto::Subjects>* writer)
{
    LOG_DBG() << "Public message handler. Subscribe subjects stream has been opened";

    return mSubjectsChangedController.HandleStream(context, writer);
}

/***********************************************************************************************************************
 * IAMPublicPermissionsService implementation
 **********************************************************************************************************************/

grpc::Status PublicMessageHandler::GetPermissions([[maybe_unused]] grpc::ServerContext* context,
    const iamproto::PermissionsRequest* request, iamproto::PermissionsResponse* response)
{
    LOG_DBG() << "Public message handler. Process get permissions: funcServerID"
              << request->functional_server_id().c_str();

    aos::InstanceIdent aosInstanceIdent;
    aos::StaticArray<aos::iam::permhandler::PermKeyValue, aos::iam::permhandler::cServicePermissionMaxCount>
        aosInstancePerm;

    auto err = GetPermHandler()->GetPermissions(
        request->secret().c_str(), request->functional_server_id().c_str(), aosInstanceIdent, aosInstancePerm);
    if (!err.IsNone()) {
        LOG_DBG() << "Public message handler. GetPermissions failed: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "GetPermissions error");
    }

    iamproto::InstanceIdent instanceIdent;
    iamproto::Permissions   permissions;

    instanceIdent.set_service_id(aosInstanceIdent.mServiceID.CStr());
    instanceIdent.set_subject_id(aosInstanceIdent.mSubjectID.CStr());
    instanceIdent.set_instance(aosInstanceIdent.mInstance);

    for (const auto& [key, val] : aosInstancePerm) {
        (*permissions.mutable_permissions())[key.CStr()] = val.CStr();
    }

    *response->mutable_instance()    = instanceIdent;
    *response->mutable_permissions() = permissions;

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPublicNodesService implementation
 **********************************************************************************************************************/

grpc::Status PublicMessageHandler::GetAllNodeIDs([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, iamproto::NodesID* response)
{
    LOG_DBG() << "Public message handler. Process get all node IDs";

    aos::StaticArray<aos::StaticString<aos::cNodeIDLen>, aos::cMaxNumNodes> nodeIDs;

    if (auto err = mNodeManager->GetAllNodeIds(nodeIDs); !err.IsNone()) {
        LOG_ERR() << "Failed to get all node IDs: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to get all node IDs");
    }

    if (nodeIDs.Size() == 0) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "Empty node IDs");
    }

    // Sort node IDs to have main node ID last
    nodeIDs.Sort([mainNodeId = mNodeInfo.mID](const auto& a, const auto&) { return a == mainNodeId; });

    for (const auto& id : nodeIDs) {
        response->add_ids(id.CStr());
    }

    return grpc::Status::OK;
}

grpc::Status PublicMessageHandler::GetNodeInfo([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const iamproto::GetNodeInfoRequest* request, iamproto::NodeInfo* response)
{
    LOG_DBG() << "Public message handler. Process get node info: id = " << request->node_id().c_str();

    aos::NodeInfo nodeInfo;

    if (auto err = mNodeManager->GetNodeInfo(request->node_id().c_str(), nodeInfo); !err.IsNone()) {
        LOG_ERR() << "Failed to get node info: " << AOS_ERROR_WRAP(err);

        return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to get node info");
    }

    ConvertToProto(nodeInfo, *response);

    return grpc::Status::OK;
}

grpc::Status PublicMessageHandler::SubscribeNodeChanged([[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const google::protobuf::Empty* request, grpc::ServerWriter<iamproto::NodeInfo>* writer)
{
    LOG_DBG() << "Public message handler. Got subscribe node changed request";

    return mNodeChangedController.HandleStream(context, writer);
}

grpc::Status PublicMessageHandler::RegisterNode(grpc::ServerContext*                            context,
    grpc::ServerReaderWriter<::iamproto::IAMIncomingMessages, ::iamproto::IAMOutgoingMessages>* stream)
{
    LOG_DBG() << "Public message handler. Process register node";

    using aos::NodeStatus;
    using aos::NodeStatusEnum;

    static const std::vector<NodeStatus> allowedStatuses = {NodeStatusEnum::eUnprovisioned};

    return GetNodeController()->HandleRegisterNodeStream(allowedStatuses, stream, context, GetNodeManager());
}
