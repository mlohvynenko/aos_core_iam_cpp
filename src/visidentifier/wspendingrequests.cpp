/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wspendingrequests.hpp"
#include <algorithm>

void PendingRequests::Add(std::shared_ptr<RequestParams> requestParamsPtr)
{
    std::lock_guard lk(mutex);
    requests.push_back(std::move(requestParamsPtr));
}

void PendingRequests::Remove(const std::string& requestId)
{
    std::lock_guard lk(mutex);

    requests.erase(std::remove_if(
        requests.begin(), requests.end(), [&requestId](const auto& item) { return item->requestId == requestId; }));
}

bool PendingRequests::SetResponse(const std::string& requestId, const std::string& response)
{
    std::lock_guard lk(mutex);

    auto itPendingMessage = std::find_if(requests.begin(), requests.end(),
        [&requestId](const auto& pendingRequest) { return pendingRequest->requestId == requestId; });

    if (itPendingMessage == requests.end())
        return false;

    (*itPendingMessage)->response = response;
    (*itPendingMessage)->rspChannel.set();

    return true;
}
