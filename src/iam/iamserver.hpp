/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IAMSERVER_HPP_
#define IAMSERVER_HPP_

#include <aos/iam/permhandler.hpp>

#include "remoteiamhandler.hpp"
#include <aos/common/cryptoutils.hpp>
#include <aos/iam/certhandler.hpp>
#include <aos/iam/identhandler.hpp>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_builder.h>
#include <string>
#include <thread>
#include <vector>

#include <iamanager.grpc.pb.h>

namespace aos {
namespace iam {

/**
 * Config
 */
struct Config {
    std::string              mIAMPublicServerURL;
    std::string              mIAMProtectedServerURL;
    std::string              mNodeID;
    std::string              mNodeType;
    std::string              mCertStorage;
    std::vector<std::string> mFinishProvisioningCmdArgs;
    std::vector<std::string> mDiskEncryptionCmdArgs;
};

/**
 * IAM GRPC server
 */
class IAMServer :
    // public services
    private iamanager::v4::IAMPublicService::Service,
    private iamanager::v4::IAMPublicIdentityService::Service,
    private iamanager::v4::IAMPublicPermissionsService::Service,
    // protected services
    private iamanager::v4::IAMCertificateService::Service,
    private iamanager::v4::IAMProvisioningService::Service,
    private iamanager::v4::IAMPermissionsService::Service,
    // identhandler subject observer interface
    public identhandler::SubjectsObserverItf {
public:
    /**
     * Initializes IAM server instance.
     *
     * @param config server configuration.
     * @param certHandler certificate handler.
     * @param identHandler identification handler.
     * @param permHandler permission handler.
     * @param remoteHandler IAM remote handler.
     * @param certLoader certificate loader.
     * @param cryptoProvider crypto provider.
     * @param provisioningMode flag indicating whether provisioning mode is active.
     */
    void Init(const Config& config, certhandler::CertHandlerItf* certHandler,
        identhandler::IdentHandlerItf* identHandler, permhandler::PermHandlerItf* permHandler,
        RemoteIAMHandlerItf* remoteHandler, cryptoutils::CertLoader& certLoader,
        crypto::x509::ProviderItf& cryptoProvider, bool provisioningMode);

    /**
     * Close IAM server instance.
     */
    void Close();

private:
    // IAMPublicService interface
    grpc::Status GetAPIVersion(grpc::ServerContext* context, const google::protobuf::Empty* request,
        iamanager::v4::APIVersion* response) override;
    grpc::Status GetNodeInfo(grpc::ServerContext* context, const google::protobuf::Empty* request,
        iamanager::v4::NodeInfo* response) override;
    grpc::Status GetCert(grpc::ServerContext* context, const iamanager::v4::GetCertRequest* request,
        iamanager::v4::GetCertResponse* response) override;

    // IAMPublicIdentityService interface
    grpc::Status GetSystemInfo(grpc::ServerContext* context, const google::protobuf::Empty* request,
        iamanager::v4::SystemInfo* response) override;
    grpc::Status GetSubjects(grpc::ServerContext* context, const google::protobuf::Empty* request,
        iamanager::v4::Subjects* response) override;
    grpc::Status SubscribeSubjectsChanged(grpc::ServerContext* context, const google::protobuf::Empty* request,
        grpc::ServerWriter<iamanager::v4::Subjects>* writer) override;

    // IAMPublicPermissionsService interface
    grpc::Status GetPermissions(grpc::ServerContext* context, const iamanager::v4::PermissionsRequest* request,
        iamanager::v4::PermissionsResponse* response) override;

    // IAMProvisioningService interface
    grpc::Status GetAllNodeIDs(grpc::ServerContext* context, const google::protobuf::Empty* request,
        iamanager::v4::NodesID* response) override;
    grpc::Status GetCertTypes(grpc::ServerContext* context, const iamanager::v4::GetCertTypesRequest* request,
        iamanager::v4::CertTypes* response) override;
    grpc::Status SetOwner(grpc::ServerContext* context, const iamanager::v4::SetOwnerRequest* request,
        google::protobuf::Empty* response) override;
    grpc::Status Clear(grpc::ServerContext* context, const iamanager::v4::ClearRequest* request,
        google::protobuf::Empty* response) override;
    grpc::Status EncryptDisk(grpc::ServerContext* context, const iamanager::v4::EncryptDiskRequest* request,
        google::protobuf::Empty* response) override;
    grpc::Status FinishProvisioning(grpc::ServerContext* context, const google::protobuf::Empty* request,
        google::protobuf::Empty* response) override;

    // IAMCertificateService interface
    grpc::Status CreateKey(grpc::ServerContext* context, const iamanager::v4::CreateKeyRequest* request,
        iamanager::v4::CreateKeyResponse* response) override;
    grpc::Status ApplyCert(grpc::ServerContext* context, const iamanager::v4::ApplyCertRequest* request,
        iamanager::v4::ApplyCertResponse* response) override;

    // IAMPermissionsService interface
    grpc::Status RegisterInstance(grpc::ServerContext* context, const iamanager::v4::RegisterInstanceRequest* request,
        iamanager::v4::RegisterInstanceResponse* response) override;
    grpc::Status UnregisterInstance(grpc::ServerContext* context,
        const iamanager::v4::UnregisterInstanceRequest* request, google::protobuf::Empty* response) override;

    // identhandler::SubjectsObserverItf interface
    Error SubjectsChanged(const Array<StaticString<cSubjectIDLen>>& messages) override;

    // executes command & returns error status and combined stderr & stdout
    Error ExecProcess(const std::string& cmd, const std::vector<std::string>& args, std::string& output);

    // creating routines
    void CreatePublicServer(const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials);
    void RegisterPublicServices(grpc::ServerBuilder& builder);

    void CreateProtectedServer(
        const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials, bool provisionMode);
    void RegisterProtectedServices(grpc::ServerBuilder& builder, bool provisionMode);

    certhandler::CertHandlerItf*   mCertHandler;
    identhandler::IdentHandlerItf* mIdentHandler;
    permhandler::PermHandlerItf*   mPermHandler;
    RemoteIAMHandlerItf*           mRemoteHandler;

    std::string              mNodeID;
    std::string              mNodeType;
    std::vector<std::string> mFinishProvisioningCmdArgs;
    std::vector<std::string> mDiskEncryptCmdArgs;

    std::unique_ptr<grpc::Server> mPublicServer, mProtectedServer;

    std::mutex                                                mSubjectSubscriptionsLock;
    std::vector<grpc::ServerWriter<iamanager::v4::Subjects>*> mSubjectSubscriptions;
};

} // namespace iam
} // namespace aos

#endif
