/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <mbedtls/pem.h>

#include "certhelper.hpp"

namespace UtilsCert {

void ParseID(const aos::String& url, aos::uuid::UUID& id)
{
    aos::StaticString<aos::cFilePathLen>       library;
    aos::StaticString<aos::pkcs11::cLabelLen>  token;
    aos::StaticString<aos::pkcs11::cLabelLen>  label;
    aos::StaticString<aos::pkcs11::cPINLength> userPIN;

    auto err = aos::cryptoutils::ParsePKCS11URL(url, library, token, label, id, userPIN);
    assert(err.IsNone());
}

void ParsePIN(const aos::String& url, aos::String& pin)
{
    aos::StaticString<aos::cFilePathLen>      library;
    aos::StaticString<aos::pkcs11::cLabelLen> token;
    aos::StaticString<aos::pkcs11::cLabelLen> label;
    aos::uuid::UUID                           id;

    auto err = aos::cryptoutils::ParsePKCS11URL(url, library, token, label, id, pin);
    assert(err.IsNone());
}

#define PEM_BEGIN_CRT "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT   "-----END CERTIFICATE-----\n"

std::string ConvertCertificateToPEM(aos::crypto::x509::Certificate& certificate)
{
    size_t olen;

    std::string result;
    mbedtls_pem_write_buffer(
        PEM_BEGIN_CRT, PEM_END_CRT, certificate.mRaw.Get(), certificate.mRaw.Size(), nullptr, result.size(), &olen);

    result.resize(olen);

    auto ret = mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, certificate.mRaw.Get(), certificate.mRaw.Size(),
        reinterpret_cast<uint8_t*>(&result[0]), result.size(), &olen);

    assert(ret == 0);

    return result;
}

aos::StaticString<aos::uuid::cUUIDLen * 3> PercentEncodeID(const aos::uuid::UUID& id)
{
    aos::StaticString<aos::uuid::cUUIDLen * 3> result;
    for (const auto& val : id) {
        aos::Pair<char, char> chunk = aos::String::ByteToHex(val);

        result.PushBack('%');
        result.PushBack(chunk.mFirst);
        result.PushBack(chunk.mSecond);
    }

    *result.end() = 0;

    return result;
}

// The PKCS #11 URI Scheme
// https://www.rfc-editor.org/rfc/rfc7512.html
aos::Error CreateURL(const aos::String& token, const aos::String& label, const aos::Array<uint8_t>& id,
    const aos::String& userPin, aos::String& url)
{
    const auto addParam = [](const char* name, const char* param, bool opaque, aos::String& paramList) {
        if (!paramList.IsEmpty()) {
            const char* delim = opaque ? ";" : "&";
            paramList.Append(delim);
        }

        paramList.Append(name).Append("=").Append(param);
    };

    aos::StaticString<aos::cURLLen> opaque, query;

    // create opaque part of url
    addParam("token", token.CStr(), true, opaque);

    if (false && !label.IsEmpty()) {
        addParam("object", label.CStr(), true, opaque);
    }

    if (!id.IsEmpty()) {
        // StaticString<uuid::cUUIDStrLen> uuid;
        // uuid.ByteArrayToHex(id);
        // StaticString<uuid::cUUIDStrLen> uuid = uuid::UUIDToString(id);
        auto uuid = PercentEncodeID(id);
        addParam("id", uuid.CStr(), true, opaque);
    }

    // create query part of url
    // doesnt' work with module-path
    // addParam("module-path", mConfig.mLibrary.CStr(), false, query);

    addParam("pin-value", userPin.CStr(), false, query);
    //(void) userPin;
    // addParam("pin-source", "file:/home/mykola_kobets/work/aos_core_lib_cpp/build/tests/utils/certificates/pin.txt",
    // false, query);

    // combine opaque & query parts of url
    auto err = url.Format("pkcs11:%s?%s", opaque.CStr(), query.CStr());
    if (!err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    std::cout << "Formatted URL: " << url.CStr() << std::endl;

    return aos::ErrorEnum::eNone;
}

std::string ConvertPrivKeyToPEM(const aos::String& keyURL)
{
    aos::StaticString<aos::cFilePathLen>       library;
    aos::StaticString<aos::pkcs11::cLabelLen>  token;
    aos::StaticString<aos::pkcs11::cLabelLen>  label;
    aos::StaticString<aos::pkcs11::cPINLength> userPIN;
    aos::uuid::UUID                            id;

    auto err = aos::cryptoutils::ParsePKCS11URL(keyURL, library, token, label, id, userPIN);
    assert(err.IsNone());

    aos::StaticString<aos::cURLLen> pkcs11URL;
    err = CreateURL(token, label, id, userPIN, pkcs11URL);
    assert(err.IsNone());

    return std::string("engine:pkcs11:") + pkcs11URL.CStr();
}

void CreateCredProvider(const aos::iam::certhandler::CertInfo& certInfo, aos::cryptoutils::CertLoaderItf& certLoaderItf,
    std::shared_ptr<grpc::experimental::CertificateProviderInterface>& provider)
{
    aos::SharedPtr<aos::crypto::x509::CertificateChain> certificates;
    aos::Error                                          err;

    Tie(certificates, err) = certLoaderItf.LoadCertsChainByURL(certInfo.mCertURL);

    auto rootCert = ConvertCertificateToPEM((*certificates)[1]);

    auto keyCertPair = grpc::experimental::IdentityKeyCertPair {
        ConvertPrivKeyToPEM(certInfo.mKeyURL), ConvertCertificateToPEM((*certificates)[0])};

    std::vector<grpc::experimental::IdentityKeyCertPair> keyCertPairs = {keyCertPair};

    provider = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(rootCert, keyCertPairs);
}

void CreateCredProviderForClient(const aos::iam::certhandler::CertInfo& certInfo,
    aos::cryptoutils::CertLoaderItf&                                    certLoaderItf,
    std::shared_ptr<grpc::experimental::CertificateProviderInterface>&  provider)
{
    aos::SharedPtr<aos::crypto::x509::CertificateChain> certificates;
    aos::Error                                          err;

    aos::Tie(certificates, err) = certLoaderItf.LoadCertsChainByURL(certInfo.mCertURL);
    assert(err.IsNone());
    assert(certificates->Size() == 2);

    auto rootCert = ConvertCertificateToPEM((*certificates)[1]);

    auto keyCertPair = grpc::experimental::IdentityKeyCertPair {
        ConvertPrivKeyToPEM(certInfo.mKeyURL), ConvertCertificateToPEM((*certificates)[0])};

    std::vector<grpc::experimental::IdentityKeyCertPair> keyCertPairs = {keyCertPair};

    provider = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(rootCert, keyCertPairs);
}

std::shared_ptr<grpc::ChannelCredentials> TlsChannelCredentials(
    const aos::iam::certhandler::CertInfo& certInfo, aos::cryptoutils::CertLoaderItf& certLoaderItf)
{
    std::shared_ptr<grpc::experimental::CertificateProviderInterface> provider;
    CreateCredProviderForClient(certInfo, certLoaderItf, provider);

    grpc::experimental::TlsChannelCredentialsOptions options;
    options.set_certificate_provider(provider);
    options.set_verify_server_certs(true);

    options.set_check_call_host(false);
    options.watch_root_certs();
    options.set_root_cert_name("root");
    options.watch_identity_key_cert_pairs();
    options.set_identity_cert_name("identity");

    return grpc::experimental::TlsCredentials(options);
}

} // namespace UtilsCert
