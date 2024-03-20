/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PERMISSIONHANDLER_HPP_
#define PERMISSIONHANDLER_HPP_

#include <aos/common/tools/string.hpp>
#include <aos/common/tools/uuid.hpp>
#include <aos/common/types.hpp>

namespace aos {
namespace iam {
namespace permhandler {

constexpr auto cPermKeyStrLen = 40;

/**
 * Maximum length of permhandler permission value string.
 */
constexpr auto cPermValueStlLen = 40;

/**
 * Maximum number of permhandler service permissions.
 */
constexpr auto cServicePermissionMaxCount = 40;

/**
 * Permission key value.
 */
struct PermKeyValue {
    StaticString<cPermKeyStrLen>   mKey;
    StaticString<cPermValueStlLen> mValue;

    /**
     * Compares permission key value.
     *
     * @param rhs object to compare.
     * @return bool.
     */
    bool operator==(const PermKeyValue& rhs) { return (mKey == rhs.mKey) && (mValue == rhs.mValue); }
};

/**
 * Functional service permissions.
 */
struct FunctionalServicePermissions {
    StaticString<cSystemIDLen>                            mName;
    StaticArray<PermKeyValue, cServicePermissionMaxCount> mPermissions;
};

/**
 * Instance permissions.
 */
struct InstancePermissions {
    StaticString<uuid::cUUIDStrLen>                            mSecretUUID;
    InstanceIdent                                              mInstanceIdent;
    StaticArray<FunctionalServicePermissions, cMaxNumServices> mFuncServicePerms;
};

/**
 * Permission handler.
 */
class PermissionHandlerItf {
public:
    /**
     * Adds new service instance and its permissions into cache.
     *
     * @param instanceIdent instance identification.
     * @param instancePermissions instance permissions.
     * @returns RetWithError<StaticString<uuid::cUUIDStrLen>>.
     */
    virtual RetWithError<StaticString<uuid::cUUIDStrLen>> RegisterInstance(
        const InstanceIdent& instanceIdent, const Array<FunctionalServicePermissions>& instancePermissions)
        = 0;

    /**
     * Unregisters instance deletes service instance with permissions from cache.
     *
     * @param instanceIdent instance identification.
     * @returns Error.
     */
    virtual Error UnregisterInstance(const InstanceIdent& instanceIdent) = 0;

    /**
     * Retruns instance ident and permissions by secret UUID and functional server ID.
     *
     * @param[out] instanceIdent result instance ident.
     * @param[out] servicePermissions result service permission.
     * @param secretUUID secret UUID.
     * @param funcServerID functional server ID.
     * @returns Error.
     */
    virtual Error GetPermissions(const String& secretUUID, const String& funcServerID, InstanceIdent& instanceIdent,
        Array<PermKeyValue>& servicePermissions)
        = 0;
};

} // namespace permhandler
} // namespace iam
} // namespace aos

#endif
