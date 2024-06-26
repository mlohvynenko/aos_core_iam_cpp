/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fstream>
#include <iostream>
#include <unordered_map>

#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>

#include "config.hpp"
#include "log.hpp"

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

class CaseInsensitiveObjectWrapper {
public:
    explicit CaseInsensitiveObjectWrapper(const Poco::JSON::Object::Ptr& object)
        : mObject(object)
    {
        for (const auto& pair : *object) {
            mKeyMap.emplace(ToLowercase(pair.first), pair.first);
        }
    }

    bool Has(const std::string& key) const
    {
        std::string lowerKey = ToLowercase(key);

        return mKeyMap.count(lowerKey) > 0;
    }

    Poco::Dynamic::Var Get(const std::string& key) const
    {
        std::string lowerKey = ToLowercase(key);
        auto        it       = mKeyMap.find(lowerKey);

        if (it == mKeyMap.end()) {
            throw Poco::NotFoundException("Key not found");
        }

        return mObject->get(it->second);
    }

    template <typename T>
    T GetValue(const std::string& key, const T& defaultValue = T {}) const
    {
        if (Has(key)) {
            return Get(key).convert<T>();
        }

        return defaultValue;
    }

    template <typename T>
    std::optional<T> GetOptionalValue(const std::string& key) const
    {
        if (Has(key)) {
            return Get(key).convert<T>();
        }

        return std::nullopt;
    }

    Poco::JSON::Array::Ptr GetArray(const std::string& key) const { return Get(key).extract<Poco::JSON::Array::Ptr>(); }

    operator Poco::JSON::Object::Ptr() const { return mObject; }

    CaseInsensitiveObjectWrapper GetObject(const std::string& key) const
    {
        Poco::Dynamic::Var value = Get(key);

        return CaseInsensitiveObjectWrapper(value.extract<Poco::JSON::Object::Ptr>());
    }

private:
    std::string ToLowercase(const std::string& str) const
    {
        std::string lowerStr = str;

        std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);

        return lowerStr;
    }

    Poco::JSON::Object::Ptr                      mObject;
    std::unordered_map<std::string, std::string> mKeyMap;
};

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

template <typename T, typename ParserFunc>
std::vector<T> GetArrayValue(const CaseInsensitiveObjectWrapper& object, const std::string& key, ParserFunc parserFunc)
{
    std::vector<T> result;

    if (!object.Has(key)) {
        return result;
    }

    Poco::JSON::Array::Ptr array = object.GetArray(key);

    std::transform(array->begin(), array->end(), std::back_inserter(result), parserFunc);

    return result;
}

static Identifier ParseIdentifier(const CaseInsensitiveObjectWrapper& object)
{
    return Identifier {object.GetValue<std::string>("Plugin"), object.Get("Params")};
}

static RemoteIAM ParseRemoteIAM(const CaseInsensitiveObjectWrapper& object)
{
    UtilsTime::Duration duration {};
    auto                requestTimeoutString = object.GetValue<std::string>("RequestTimeout");

    if (!requestTimeoutString.empty()) {
        auto ret = UtilsTime::ParseDuration(requestTimeoutString);

        if (!ret.mError.IsNone()) {
            throw std::runtime_error("Error parsing duration");
        }

        duration = ret.mValue;
    }

    return RemoteIAM {object.GetValue<std::string>("NodeID"), object.GetValue<std::string>("URL"), duration};
}

static ModuleConfig ParseModuleConfig(const CaseInsensitiveObjectWrapper& object)
{
    return ModuleConfig {
        object.GetValue<std::string>("ID"),
        object.GetValue<std::string>("Plugin"),
        object.GetValue<std::string>("Algorithm"),
        object.GetValue<int>("MaxItems"),
        GetArrayValue<std::string>(
            object, "ExtendedKeyUsage", [](const Poco::Dynamic::Var& value) { return value.convert<std::string>(); }),
        GetArrayValue<std::string>(
            object, "AlternativeNames", [](const Poco::Dynamic::Var& value) { return value.convert<std::string>(); }),
        object.GetValue<bool>("Disabled"),
        object.GetValue<bool>("SkipValidation"),
        object.Get("Params"),
    };
}

/***********************************************************************************************************************
 * Public functions
 **********************************************************************************************************************/

aos::RetWithError<Config> ParseConfig(const std::string& filename)
{
    std::ifstream file(filename);

    if (!file.is_open()) {
        return {Config {}, aos::ErrorEnum::eNotFound};
    }

    Config config {};

    try {
        Poco::JSON::Parser           parser;
        auto                         result = parser.parse(file);
        CaseInsensitiveObjectWrapper object(result.extract<Poco::JSON::Object::Ptr>());

        config.mIAMPublicServerURL       = object.GetValue<std::string>("IAMPublicServerURL");
        config.mIAMProtectedServerURL    = object.GetValue<std::string>("IAMProtectedServerURL");
        config.mNodeID                   = object.GetValue<std::string>("NodeID");
        config.mNodeType                 = object.GetValue<std::string>("NodeType");
        config.mCACert                   = object.GetValue<std::string>("CACert");
        config.mCertStorage              = object.GetValue<std::string>("CertStorage");
        config.mWorkingDir               = object.GetValue<std::string>("WorkingDir");
        config.mEnablePermissionsHandler = object.GetValue<bool>("EnablePermissionsHandler");

        config.mFinishProvisioningCmdArgs = GetArrayValue<std::string>(object, "FinishProvisioningCmdArgs",
            [](const Poco::Dynamic::Var& value) { return value.convert<std::string>(); });

        config.mDiskEncryptionCmdArgs = GetArrayValue<std::string>(object, "DiskEncryptionCmdArgs",
            [](const Poco::Dynamic::Var& value) { return value.convert<std::string>(); });

        config.mCertModules = GetArrayValue<ModuleConfig>(object, "CertModules", [](const Poco::Dynamic::Var& value) {
            return ParseModuleConfig(CaseInsensitiveObjectWrapper(value.extract<Poco::JSON::Object::Ptr>()));
        });

        config.mRemoteIAMs = GetArrayValue<RemoteIAM>(object, "RemoteIAMs", [](const Poco::Dynamic::Var& value) {
            return ParseRemoteIAM(CaseInsensitiveObjectWrapper(value.extract<Poco::JSON::Object::Ptr>()));
        });

        if (object.Has("Identifier")) {
            config.mIdentifier = ParseIdentifier(object.GetObject("Identifier"));
        }
    } catch (const std::exception& e) {
        LOG_ERR() << "Error parsing config: " << e.what();

        return {Config {}, aos::ErrorEnum::eInvalidArgument};
    }

    return config;
}

aos::RetWithError<PKCS11ModuleParams> ParsePKCS11ModuleParams(Poco::Dynamic::Var params)
{
    PKCS11ModuleParams moduleParams;

    try {
        CaseInsensitiveObjectWrapper object(params.extract<Poco::JSON::Object::Ptr>());

        moduleParams.mLibrary         = object.GetValue<std::string>("library");
        moduleParams.mSlotID          = object.GetOptionalValue<uint32_t>("slotID");
        moduleParams.mSlotIndex       = object.GetOptionalValue<int>("slotIndex");
        moduleParams.mTokenLabel      = object.GetValue<std::string>("tokenLabel");
        moduleParams.mUserPINPath     = object.GetValue<std::string>("userPinPath");
        moduleParams.mModulePathInURL = object.GetValue<bool>("modulePathInUrl");
        moduleParams.mUID             = object.GetOptionalValue<uint32_t>("uid").value_or(0);
        moduleParams.mGID             = object.GetOptionalValue<uint32_t>("gid").value_or(0);

    } catch (const std::exception& e) {
        LOG_ERR() << "Error parsing PKCS11 module params: " << e.what();

        return {PKCS11ModuleParams {}, aos::ErrorEnum::eInvalidArgument};
    }

    return moduleParams;
}

aos::RetWithError<VISIdentifierModuleParams> ParseVISIdentifierModuleParams(Poco::Dynamic::Var params)
{
    VISIdentifierModuleParams moduleParams;

    try {
        CaseInsensitiveObjectWrapper object(params.extract<Poco::JSON::Object::Ptr>());

        moduleParams.mVISServer        = object.GetValue<std::string>("visServer");
        moduleParams.mCaCertFile       = object.GetValue<std::string>("caCertFile");
        moduleParams.mWebSocketTimeout = object.GetValue<int>("webSocketTimeout");

    } catch (const std::exception& e) {
        LOG_ERR() << "Error parsing VIS identifier module params: " << e.what();

        return {VISIdentifierModuleParams {}, aos::ErrorEnum::eInvalidArgument};
    }

    return moduleParams;
}
