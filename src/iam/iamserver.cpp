/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "iamserver.hpp"

#include "log.hpp"
#include <Poco/Pipe.h>
#include <Poco/PipeStream.h>
#include <Poco/Process.h>
#include <aos/common/crypto.hpp>
#include <aos/common/cryptoutils.hpp>
#include <aos/common/tools/string.hpp>
#include <aos/common/types.hpp>
#include <aos/iam/certhandler.hpp>
#include <memory>
#include <utils/exception.hpp>

namespace aos {
namespace iam {

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

constexpr auto cDiscEncryptionType = "diskencryption";
constexpr auto cIamAPIVersion      = 4;
const int      cMaxSubjectsCount   = 10;

/***********************************************************************************************************************
 * Statics
 **********************************************************************************************************************/

static StaticString<uuid::cUUIDLen * 3> PercentEncodeID(const uuid::UUID& id)
{
    StaticString<uuid::cUUIDLen * 3> result;

    for (const auto& val : id) {
        aos::Pair<char, char> chunk = String::ByteToHex(val);

        result.PushBack('%');
        result.PushBack(chunk.mFirst);
        result.PushBack(chunk.mSecond);
    }

    *result.end() = 0;

    return result;
}

// The PKCS #11 URI Scheme: https://www.rfc-editor.org/rfc/rfc7512.html
static std::string CreateRFC7512URL(
    const String& token, const String& label, const Array<uint8_t>& id, const String& userPin)
{
    const auto addParam = [](const char* name, const char* param, bool opaque, std::string& paramList) {
        if (!paramList.empty()) {
            const char* delim = opaque ? ";" : "&";
            paramList.append(delim);
        }

        paramList += std::string(name) + "=" + param;
    };

    std::string opaque, query;

    // create opaque part of url
    addParam("token", token.CStr(), true, opaque);

    (void)label; // label is not required, id should be enough to identify the object

    if (!id.IsEmpty()) {
        auto uuid = PercentEncodeID(id);
        addParam("id", uuid.CStr(), true, opaque);
    }

    addParam("pin-value", userPin.CStr(), false, query);

    // combine opaque & query parts of url
    StaticString<cURLLen> url;

    auto err = url.Format("pkcs11:%s?%s", opaque.c_str(), query.c_str());
    AOS_ERROR_CHECK_AND_THROW("RFC7512 URL format problem", err);

    return url.CStr();
}

static std::string CreatePKCS11URL(const String& keyURL)
{
    StaticString<cFilePathLen>       library;
    StaticString<pkcs11::cLabelLen>  token;
    StaticString<pkcs11::cLabelLen>  label;
    StaticString<pkcs11::cPINLength> userPIN;
    uuid::UUID                       id;

    auto err = cryptoutils::ParsePKCS11URL(keyURL, library, token, label, id, userPIN);
    AOS_ERROR_CHECK_AND_THROW("URL parsing problem", err);

    return "engine:pkcs11:" + CreateRFC7512URL(token, label, id, userPIN);
}

static std::string ConvertCertificateToPEM(
    const crypto::x509::Certificate& certificate, crypto::x509::ProviderItf& cryptoProvider)
{
    std::string result;

    result.resize(crypto::cCertPEMLen);

    String view = result.c_str();

    view.Resize(crypto::cCertPEMLen);

    auto err = cryptoProvider.X509CertToPEM(certificate, view);
    AOS_ERROR_CHECK_AND_THROW("Certificate convertion problem", err);

    result.resize(view.Size());

    return result;
}

static std::shared_ptr<grpc::experimental::CertificateProviderInterface> GetMTLSCertificates(
    const certhandler::CertInfo& certInfo, cryptoutils::CertLoader& certLoader,
    crypto::x509::ProviderItf& cryptoProvider)
{
    auto [certificates, err] = certLoader.LoadCertsChainByURL(certInfo.mCertURL);

    AOS_ERROR_CHECK_AND_THROW("Load certificate by URL failed", err);

    if (certificates->Size() != 2) {
        throw std::runtime_error("Not expected number of certificates in the chain");
    }

    auto rootCert = ConvertCertificateToPEM((*certificates)[1], cryptoProvider);

    auto keyCertPair = grpc::experimental::IdentityKeyCertPair {
        CreatePKCS11URL(certInfo.mKeyURL), ConvertCertificateToPEM((*certificates)[0], cryptoProvider)};

    std::vector<grpc::experimental::IdentityKeyCertPair> keyCertPairs = {keyCertPair};

    return std::make_shared<grpc::experimental::StaticDataCertificateProvider>(rootCert, keyCertPairs);
}

static std::shared_ptr<grpc::experimental::CertificateProviderInterface> GetTLSCertificates(
    const certhandler::CertInfo& certInfo, cryptoutils::CertLoader& certLoader,
    crypto::x509::ProviderItf& cryptoProvider)
{
    auto [certificates, err] = certLoader.LoadCertsChainByURL(certInfo.mCertURL);

    AOS_ERROR_CHECK_AND_THROW("Load certificate by URL failed", err);

    if (certificates->Size() < 1) {
        throw std::runtime_error("Not expected number of certificates in the chain");
    }

    auto keyCertPair = grpc::experimental::IdentityKeyCertPair {
        CreatePKCS11URL(certInfo.mKeyURL), ConvertCertificateToPEM((*certificates)[0], cryptoProvider)};

    std::vector<grpc::experimental::IdentityKeyCertPair> keyCertPairs = {keyCertPair};

    return std::make_shared<grpc::experimental::StaticDataCertificateProvider>("", keyCertPairs);
}

static std::shared_ptr<grpc::ServerCredentials> GetMTLSCredentials(const certhandler::CertInfo& certInfo,
    cryptoutils::CertLoader& certLoader, crypto::x509::ProviderItf& cryptoProvider)
{
    auto certificates = GetMTLSCertificates(certInfo, certLoader, cryptoProvider);

    grpc::experimental::TlsServerCredentialsOptions options {certificates};

    options.set_cert_request_type(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
    options.set_check_call_host(false);
    options.watch_root_certs();
    options.watch_identity_key_cert_pairs();
    options.set_root_cert_name("root");
    options.set_identity_cert_name("identity");

    return grpc::experimental::TlsServerCredentials(options);
}

static std::shared_ptr<grpc::ServerCredentials> GetTLSCredentials(const certhandler::CertInfo& certInfo,
    cryptoutils::CertLoader& certLoader, crypto::x509::ProviderItf& cryptoProvider)
{
    auto certificates = GetTLSCertificates(certInfo, certLoader, cryptoProvider);

    grpc::experimental::TlsServerCredentialsOptions options {certificates};

    options.set_cert_request_type(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    options.set_check_call_host(false);
    options.watch_identity_key_cert_pairs();
    options.set_identity_cert_name("identity");

    return grpc::experimental::TlsServerCredentials(options);
}

const Array<uint8_t> ConvertByteArrayToAOS(const std::string& arr)
{
    return {reinterpret_cast<const uint8_t*>(arr.c_str()), arr.length()};
}

std::string ConvertByteArrayToProto(const Array<uint8_t>& arr)
{
    return std::string(reinterpret_cast<const char*>(arr.Get()), arr.Size());
}

template <size_t Size>
void ConvertToProto(const Array<StaticString<Size>>& src, google::protobuf::RepeatedPtrField<std::string>& dst)
{
    for (const auto& val : src) {
        dst.Add(val.CStr());
    }
}

aos::InstanceIdent ConvertToAOS(const iamanager::v4::InstanceIdent& val)
{
    aos::InstanceIdent result;

    result.mServiceID = val.service_id().c_str();
    result.mSubjectID = val.subject_id().c_str();
    result.mInstance  = val.instance();

    return result;
}

void ConvertToProto(const Array<StaticString<cSubjectIDLen>>& src, iamanager::v4::Subjects& dst)
{
    dst.clear_subjects();

    for (const auto& subject : src) {
        dst.add_subjects(subject.CStr());
    }
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

void IAMServer::Init(const Config& config, certhandler::CertHandlerItf* certHandler,
    identhandler::IdentHandlerItf* identHandler, permhandler::PermissionHandlerItf* permHandler,
    RemoteIAMHandlerItf* remoteHandler, cryptoutils::CertLoader& certLoader, crypto::x509::ProviderItf& cryptoProvider,
    bool provisioningMode)
{
    mCertHandler               = certHandler;
    mIdentHandler              = identHandler;
    mPermHandler               = permHandler;
    mRemoteHandler             = remoteHandler;
    mNodeID                    = config.mNodeID;
    mNodeType                  = config.mNodeType;
    mFinishProvisioningCmdArgs = config.mFinishProvisioningCmdArgs;
    mDiskEncryptCmdArgs        = config.mDiskEncryptionCmdArgs;

    std::shared_ptr<grpc::ServerCredentials> publicOpt, protectedOpt;
    if (!provisioningMode) {
        certhandler::CertInfo certInfo;

        auto err = mCertHandler->GetCertificate(aos::String(config.mCertStorage.c_str()), {}, {}, certInfo);
        AOS_ERROR_CHECK_AND_THROW("Get certificates error", err);

        publicOpt    = GetTLSCredentials(certInfo, certLoader, cryptoProvider);
        protectedOpt = GetMTLSCredentials(certInfo, certLoader, cryptoProvider);
    } else {
        publicOpt    = grpc::InsecureServerCredentials();
        protectedOpt = grpc::InsecureServerCredentials();
    }

    CreatePublicServer(config.mIAMPublicServerURL, publicOpt);
    CreateProtectedServer(config.mIAMPublicServerURL, protectedOpt, provisioningMode);
}

void IAMServer::Close()
{
    mPublicServer->Shutdown();
    mProtectedServer->Shutdown();

    mPublicServer->Wait();
    mProtectedServer->Wait();
}

/***********************************************************************************************************************
 * IAMPublicService implementation
 **********************************************************************************************************************/

grpc::Status IAMServer::GetAPIVersion(
    grpc::ServerContext* context, const google::protobuf::Empty* request, iamanager::v4::APIVersion* response)
{
    (void)context;
    (void)request;

    LOG_DBG() << "Process get API version";

    response->set_version(cIamAPIVersion);

    return grpc::Status::OK;
}

grpc::Status IAMServer::GetNodeInfo(
    grpc::ServerContext* context, const google::protobuf::Empty* request, iamanager::v4::NodeInfo* response)
{
    (void)context;
    (void)request;

    LOG_DBG() << "Process get node info";

    response->set_node_id(mNodeID);
    response->set_node_type(mNodeType);

    return grpc::Status::OK;
}

grpc::Status IAMServer::GetCert(grpc::ServerContext* context, const iamanager::v4::GetCertRequest* request,
    iamanager::v4::GetCertResponse* response)
{
    (void)context;

    LOG_DBG() << "Process get cert request: type=" << request->type().c_str()
              << ", serial=" << request->serial().c_str();

    response->set_type(request->type());

    auto issuer = ConvertByteArrayToAOS(request->issuer());

    StaticArray<uint8_t, crypto::cSerialNumSize> serial;

    auto err = String(request->serial().c_str()).HexToByteArray(serial);
    if (!err.IsNone()) {
        LOG_ERR() << "Serial conversion failed: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Serial conversion failed");
    }

    certhandler::CertInfo certInfo;

    err = mCertHandler->GetCertificate(request->type().c_str(), issuer, serial, certInfo);
    if (!err.IsNone()) {
        LOG_ERR() << "Get certificate error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get certificate error");
    }

    response->set_key_url(certInfo.mKeyURL.CStr());
    response->set_cert_url(certInfo.mCertURL.CStr());

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPublicIdentityService implementation
 **********************************************************************************************************************/

grpc::Status IAMServer::GetSystemInfo(
    grpc::ServerContext* context, const google::protobuf::Empty* request, iamanager::v4::SystemInfo* response)
{
    (void)context;
    (void)request;

    LOG_DBG() << "Process get system info";

    auto [systemID, err1] = mIdentHandler->GetSystemID();

    if (!err1.IsNone()) {
        LOG_DBG() << "Get system ID error: " << err1;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get system ID error");
    }

    auto [boardModel, err2] = mIdentHandler->GetUnitModel();
    if (!err2.IsNone()) {
        LOG_DBG() << "Get board model error: " << err2;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get board model error");
    }

    response->set_system_id(systemID.CStr());
    response->set_unit_model(boardModel.CStr());

    return grpc::Status::OK;
}

grpc::Status IAMServer::GetSubjects(
    grpc::ServerContext* context, const google::protobuf::Empty* request, iamanager::v4::Subjects* response)
{
    (void)context;
    (void)request;

    LOG_DBG() << "Process get subjects";

    aos::StaticArray<aos::StaticString<aos::cSubjectIDLen>, cMaxSubjectsCount> subjects;

    auto err = mIdentHandler->GetSubjects(subjects);

    if (!err.IsNone()) {
        LOG_DBG() << "Get subjects error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get subjects error");
    }

    for (const auto& subj : subjects) {
        response->add_subjects(subj.CStr());
    }

    return grpc::Status::OK;
}

// Error SubjectsChanged(const Array<StaticString<cSubjectIDLen>>& messages) = 0;

grpc::Status IAMServer::SubscribeSubjectsChanged(grpc::ServerContext* context, const google::protobuf::Empty* request,
    grpc::ServerWriter<iamanager::v4::Subjects>* writer)
{
    (void)context;
    (void)request;

    std::lock_guard<std::mutex> lock(mSubjectSubscriptionsLock);

    mSubjectSubscriptions.push_back(writer);

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPublicPermissionsService implementation
 **********************************************************************************************************************/

grpc::Status IAMServer::GetPermissions(grpc::ServerContext* context, const iamanager::v4::PermissionsRequest* request,
    iamanager::v4::PermissionsResponse* response)
{
    (void)context;

    LOG_DBG() << "Process get permissions: funcServerID" << request->functional_server_id().c_str();

    InstanceIdent                                                                   aosInstanceIdent;
    StaticArray<permhandler::PermKeyValue, permhandler::cServicePermissionMaxCount> aosInstancePerm;

    auto err = mPermHandler->GetPermissions(
        request->secret().c_str(), request->functional_server_id().c_str(), aosInstanceIdent, aosInstancePerm);
    if (!err.IsNone()) {
        LOG_DBG() << "GetPermissions error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "GetPermissions error");
    }

    iamanager::v4::InstanceIdent instanceIdent;
    iamanager::v4::Permissions   permissions;

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
 * IAMPublicPermissionsService implementation
 **********************************************************************************************************************/

grpc::Status IAMServer::GetAllNodeIDs(
    grpc::ServerContext* context, const google::protobuf::Empty* request, iamanager::v4::NodesID* response)
{
    (void)context;
    (void)request;

    LOG_DBG() << "Process get all node IDs";

    response->add_ids(mNodeID.c_str());

    if (!mRemoteHandler) {
        return grpc::Status::OK;
    }

    const auto& remoteNodes = mRemoteHandler->GetRemoteNodes();

    for (const auto& node : remoteNodes) {
        response->add_ids(node.CStr());
    }

    return grpc::Status::OK;
}

grpc::Status IAMServer::GetCertTypes(
    grpc::ServerContext* context, const iamanager::v4::GetCertTypesRequest* request, iamanager::v4::CertTypes* response)
{
    (void)context;

    LOG_DBG() << "Process get cert types: nodeID=" << request->node_id().c_str();

    const auto& nodeId = request->node_id();
    Error       err    = ErrorEnum::eNone;
    StaticArray<StaticString<certhandler::cCertTypeLen>, certhandler::cIAMCertModulesMaxCount> certTypes;

    if (nodeId == mNodeID || nodeId.empty()) {
        err = mCertHandler->GetCertTypes(certTypes);
    } else if (!mRemoteHandler) {
        err = mRemoteHandler->GetCertTypes(mNodeID.c_str(), certTypes);
    } else {
        LOG_DBG() << "unknown node ID";

        return grpc::Status(grpc::StatusCode::INTERNAL, "unknown node ID");
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Get certificate types error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Get certificate types error");
    }

    ConvertToProto(certTypes, *response->mutable_types());
    return grpc::Status::OK;
}

grpc::Status IAMServer::SetOwner(
    grpc::ServerContext* context, const iamanager::v4::SetOwnerRequest* request, google::protobuf::Empty* response)
{
    (void)context;
    (void)response;

    LOG_DBG() << "Process set owner request: type=" << request->type().c_str()
              << ", nodeID=" << request->node_id().c_str();

    const auto& nodeId   = request->node_id();
    const auto  certType = String(request->type().c_str());
    const auto  password = String(request->password().c_str());
    Error       err      = ErrorEnum::eNone;

    if (nodeId == mNodeID || nodeId.empty()) {
        err = mCertHandler->SetOwner(certType, password);
    } else if (!mRemoteHandler) {
        err = mRemoteHandler->SetOwner(mNodeID.c_str(), certType, password);
    } else {
        LOG_DBG() << "unknown node ID";

        return grpc::Status(grpc::StatusCode::INTERNAL, "unknown node ID");
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Set owner error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Set owner error");
    }

    return grpc::Status::OK;
}

grpc::Status IAMServer::Clear(
    grpc::ServerContext* context, const iamanager::v4::ClearRequest* request, google::protobuf::Empty* response)
{
    (void)context;
    (void)response;

    LOG_DBG() << "Process clear request: type=" << request->type().c_str() << ", nodeID=" << request->node_id().c_str();

    const auto& nodeId   = request->node_id();
    const auto  certType = String(request->type().c_str());
    Error       err      = ErrorEnum::eNone;

    if (nodeId == mNodeID || nodeId.empty()) {
        err = mCertHandler->Clear(certType);
    } else if (!mRemoteHandler) {
        err = mRemoteHandler->Clear(mNodeID.c_str(), certType);
    } else {
        LOG_DBG() << "unknown node ID";

        return grpc::Status(grpc::StatusCode::INTERNAL, "unknown node ID");
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Clear error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Clear error");
    }

    return grpc::Status::OK;
}

grpc::Status IAMServer::EncryptDisk(
    grpc::ServerContext* context, const iamanager::v4::EncryptDiskRequest* request, google::protobuf::Empty* response)
{
    (void)context;
    (void)response;

    LOG_DBG() << "Process encrypt disk request: nodeID=" << request->node_id().c_str();

    const auto& nodeId   = request->node_id();
    const auto  password = String(request->password().c_str());
    Error       err      = ErrorEnum::eNone;

    if (nodeId == mNodeID || nodeId.empty()) {
        err = mCertHandler->CreateSelfSignedCert(cDiscEncryptionType, password);

        if (!err.IsNone()) {
            LOG_ERR() << "Encrypt disk error: " << err;

            return grpc::Status(grpc::StatusCode::INTERNAL, "Encrypt disk error");
        }

        if (mDiskEncryptCmdArgs.empty()) {
            LOG_DBG() << "Bad configuration: encryption command is not specified.";

            return grpc::Status(grpc::StatusCode::INTERNAL, "Bad configuration");
        }

        const std::vector<std::string> args {mDiskEncryptCmdArgs.begin() + 1, mDiskEncryptCmdArgs.end()};

        std::string output;

        err = ExecProcess(mDiskEncryptCmdArgs[0], args, output);
    } else if (!mRemoteHandler) {
        err = mRemoteHandler->EncryptDisk(nodeId.c_str(), password);
    } else {
        LOG_DBG() << "unknown node ID";

        return grpc::Status(grpc::StatusCode::INTERNAL, "unknown node ID");
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Encrypt disk error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Encrypt disk error");
    }

    return grpc::Status::OK;
}

grpc::Status IAMServer::FinishProvisioning(
    grpc::ServerContext* context, const google::protobuf::Empty* request, google::protobuf::Empty* response)
{
    (void)context;
    (void)request;
    (void)response;

    LOG_DBG() << "Process finish provisioning request";

    Error err = ErrorEnum::eNone;

    if (mRemoteHandler) {
        for (const auto& node : mRemoteHandler->GetRemoteNodes()) {
            auto nodeErr = mRemoteHandler->FinishProvisioning(node);

            if (!nodeErr.IsNone() && err.IsNone()) {
                err = nodeErr;
            }
        }
    }

    if (!mFinishProvisioningCmdArgs.empty()) {
        std::string                    output;
        const std::vector<std::string> args {mFinishProvisioningCmdArgs.begin() + 1, mFinishProvisioningCmdArgs.end()};
        auto                           execErr = ExecProcess(mFinishProvisioningCmdArgs[0], args, output);

        if (!execErr.IsNone() && err.IsNone()) {
            err = execErr;

            LOG_ERR() << "message: " << output.c_str() << ", err: " << err;
        }
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Finish provisioning error: " << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Finish provisioning error");
    }

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMCertificateService implementation
 **********************************************************************************************************************/

grpc::Status IAMServer::CreateKey(grpc::ServerContext* context, const iamanager::v4::CreateKeyRequest* request,
    iamanager::v4::CreateKeyResponse* response)
{
    (void)context;

    const auto                 nodeID   = request->node_id();
    const auto                 certType = String(request->type().c_str());
    StaticString<cSystemIDLen> subject  = request->subject().c_str();
    const auto                 password = String(request->password().c_str());

    LOG_DBG() << "Process create key request: type=" << certType << ", nodeID=" << nodeID.c_str()
              << ", subject=" << subject;

    if (subject.IsEmpty() && !mIdentHandler) {
        LOG_ERR() << "Subject can't be empty";

        return grpc::Status(grpc::StatusCode::INTERNAL, "Subject can't be empty");
    }

    Error err = ErrorEnum::eNone;
    if (subject.IsEmpty() && mIdentHandler) {
        Tie(subject, err) = mIdentHandler->GetSystemID();
        if (!err.IsNone()) {
            LOG_ERR() << "GetSystemID returned error=" << err;

            return grpc::Status(grpc::StatusCode::INTERNAL, "GetSystemID returned error");
        }
    }

    StaticString<crypto::cCSRPEMLen> csr;

    if (nodeID == mNodeID || nodeID.empty()) {
        err = mCertHandler->CreateKey(certType, subject, password, csr);
    } else if (!mRemoteHandler) {
        err = mRemoteHandler->CreateKey(nodeID.c_str(), certType, subject, password, csr);
    } else {
        LOG_DBG() << "unknown node ID";

        return grpc::Status(grpc::StatusCode::INTERNAL, "unknown node ID");
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Create key request failed: err=" << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Create key request failed");
    }

    response->set_node_id(nodeID);
    response->set_type(certType.CStr());
    response->set_csr(csr.CStr());

    return grpc::Status::OK;
}

grpc::Status IAMServer::ApplyCert(grpc::ServerContext* context, const iamanager::v4::ApplyCertRequest* request,
    iamanager::v4::ApplyCertResponse* response)
{
    (void)context;

    const auto nodeID   = request->node_id();
    const auto certType = String(request->type().c_str());
    const auto pemCert  = String(request->cert().c_str());

    LOG_DBG() << "Process apply cert request: type=" << certType << ", nodeID=" << nodeID.c_str();

    Error                 err = ErrorEnum::eNone;
    certhandler::CertInfo certInfo;

    if (nodeID == mNodeID || nodeID.empty()) {
        err = mCertHandler->ApplyCertificate(certType, pemCert, certInfo);
    } else if (!mRemoteHandler) {
        err = mRemoteHandler->ApplyCertificate(nodeID.c_str(), certType, pemCert, certInfo);
    } else {
        LOG_DBG() << "unknown node ID";

        return grpc::Status(grpc::StatusCode::INTERNAL, "unknown node ID");
    }

    if (!err.IsNone()) {
        LOG_ERR() << "Apply cert request failed: err=" << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Apply cert request failed");
    }

    response->set_node_id(nodeID);
    response->set_type(certType.CStr());
    response->set_cert_url(certInfo.mCertURL.CStr());
    response->set_serial(ConvertByteArrayToProto(certInfo.mSerial));

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * IAMPermissionsService implementation
 **********************************************************************************************************************/

grpc::Status IAMServer::RegisterInstance(grpc::ServerContext* context,
    const iamanager::v4::RegisterInstanceRequest* request, iamanager::v4::RegisterInstanceResponse* response)
{
    (void)context;

    aos::Error err         = aos::ErrorEnum::eNone;
    const auto aosInstance = ConvertToAOS(request->instance());

    LOG_DBG() << "Process register instance: serviceID=" << aosInstance.mServiceID
              << ", subjectID=" << aosInstance.mSubjectID << ", instance=" << aosInstance.mInstance;

    // Convert permissions
    StaticArray<permhandler::FunctionalServicePermissions, cMaxNumServices> aosPermissions;

    for (const auto& [service, permissions] : request->permissions()) {
        err = aosPermissions.PushBack({});
        if (!err.IsNone() || permissions.permissions_size() > permhandler::cServicePermissionMaxCount) {
            LOG_ERR() << "Permissions allocation problem";

            return grpc::Status(grpc::StatusCode::INTERNAL, "Permissions allocation problem");
        }

        permhandler::FunctionalServicePermissions& servicePerm = aosPermissions.Back().mValue;
        servicePerm.mName                                      = service.c_str();

        for (const auto& [key, val] : permissions.permissions()) {
            servicePerm.mPermissions.PushBack({key.c_str(), val.c_str()});
        }
    }

    StaticString<uuid::cUUIDStrLen> secret;

    Tie(secret, err) = mPermHandler->RegisterInstance(aosInstance, aosPermissions);

    if (!err.IsNone()) {
        LOG_ERR() << "Register instance error: err=" << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Register instance error");
    }

    response->set_secret(secret.CStr());

    return grpc::Status::OK;
}

grpc::Status IAMServer::UnregisterInstance(grpc::ServerContext* context,
    const iamanager::v4::UnregisterInstanceRequest* request, google::protobuf::Empty* response)
{
    (void)context;
    (void)response;

    const auto instance = ConvertToAOS(request->instance());

    LOG_DBG() << "Process unregister instance: serviceID=" << instance.mServiceID
              << ", subjectID=" << instance.mSubjectID << ", instance=" << instance.mInstance;

    const auto err = mPermHandler->UnregisterInstance(instance);
    if (!err.IsNone()) {
        LOG_ERR() << "Unregister instance error: err=" << err;

        return grpc::Status(grpc::StatusCode::INTERNAL, "Unregister instance error");
    }

    return grpc::Status::OK;
}

/***********************************************************************************************************************
 * SubjectsObserverItf implementation
 **********************************************************************************************************************/

Error IAMServer::SubjectsChanged(const Array<StaticString<cSubjectIDLen>>& messages)
{
    std::lock_guard<std::mutex> lock(mSubjectSubscriptionsLock);
    iamanager::v4::Subjects     subjects;

    ConvertToProto(messages, subjects);

    for (const auto writer : mSubjectSubscriptions) {
        writer->Write(subjects);
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Auxiliary private methods
 **********************************************************************************************************************/

Error IAMServer::ExecProcess(const std::string& cmd, const std::vector<std::string>& args, std::string& output)
{
    Poco::Pipe outPipe;
    Poco::Pipe errPipe;

    Poco::ProcessHandle ph = Poco::Process::launch(cmd, args, nullptr, &outPipe, &errPipe);

    outPipe.close(Poco::Pipe::CLOSE_WRITE);
    errPipe.close(Poco::Pipe::CLOSE_WRITE);

    Poco::PipeInputStream outStream(outPipe);
    Poco::PipeInputStream errStream(errPipe);

    std::string line;

    while (std::getline(outStream, line)) {
        output += line + "\n";
    }

    while (std::getline(errStream, line)) {
        output += line + "\n";
    }

    int exitCode = ph.wait();

    return exitCode == 0 ? ErrorEnum::eNone : ErrorEnum::eFailed;
}

void IAMServer::CreatePublicServer(const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials)
{
    grpc::ServerBuilder builder;

    builder.AddListeningPort(addr, credentials);

    RegisterPublicServices(builder);

    mPublicServer = builder.BuildAndStart();
}

void IAMServer::RegisterPublicServices(grpc::ServerBuilder& builder)
{
    using namespace iamanager::v4;

    builder.RegisterService(static_cast<IAMPublicService::Service*>(this));

    if (mIdentHandler != nullptr) {
        builder.RegisterService(static_cast<IAMPublicIdentityService::Service*>(this));
    }

    if (mPermHandler != nullptr) {
        builder.RegisterService(static_cast<IAMPublicPermissionsService::Service*>(this));
    }
}

void IAMServer::CreateProtectedServer(
    const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials, bool provisionMode)
{
    grpc::ServerBuilder builder;

    builder.AddListeningPort(addr, credentials);

    RegisterPublicServices(builder);
    RegisterProtectedServices(builder, provisionMode);

    mProtectedServer = builder.BuildAndStart();
}

void IAMServer::RegisterProtectedServices(grpc::ServerBuilder& builder, bool provisionMode)
{
    using namespace iamanager::v4;

    builder.RegisterService(static_cast<IAMCertificateService::Service*>(this));

    if (provisionMode) {
        builder.RegisterService(static_cast<IAMProvisioningService::Service*>(this));
    }

    if (mPermHandler != nullptr) {
        builder.RegisterService(static_cast<IAMPermissionsService::Service*>(this));
    }
}

} // namespace iam
} // namespace aos
