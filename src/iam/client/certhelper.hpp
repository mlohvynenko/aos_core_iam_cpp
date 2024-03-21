/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CERTHELPER_HPP_
#define CERTHELPER_HPP_

#include <memory>

#include <grpcpp/security/credentials.h>

#include <aos/common/cryptoutils.hpp>

#include "aos/iam/certhandler.hpp"

namespace UtilsCert {
std::shared_ptr<grpc::ChannelCredentials> TlsChannelCredentials(
    const aos::iam::certhandler::CertInfo& certInfo, aos::cryptoutils::CertLoaderItf& certLoaderItf);
}

#endif
