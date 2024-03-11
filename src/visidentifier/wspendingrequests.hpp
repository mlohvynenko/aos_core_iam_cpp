/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WS_PENDING_REQUESTS_HPP_
#define WS_PENDING_REQUESTS_HPP_

#include <Poco/Event.h>
#include <memory>
#include <mutex>
#include <vector>

/**
 * Request Params.
 */
struct RequestParams {
    /**
     * Creates Request Params instance.
     *
     * @param requestId request id.
     */
    RequestParams(const std::string& requestId)
        : requestId(requestId)
    {
    }

    std::string requestId;
    std::string response;
    Poco::Event rspChannel;
};

/**
 * Pending Requests.
 */
class PendingRequests {
public:
    /**
     * Add request
     *
     * @param requestParamsPtr request params pointer.
     */
    void Add(std::shared_ptr<RequestParams> requestParamsPtr);

    /**
     * Remove request
     *
     * @param requestId request id.
     */
    void Remove(const std::string& requestId);

    /**
     * Set request response
     *
     * @param requestId request id.
     * @param response response.
     */
    bool SetResponse(const std::string& requestId, const std::string& response);

private:
    std::mutex mutex;

    std::vector<std::shared_ptr<RequestParams>> requests;
};

#endif
