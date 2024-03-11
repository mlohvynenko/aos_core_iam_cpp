/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WS_EXCEPTION_HPP_
#define WS_EXCEPTION_HPP_

#include "utils/exception.hpp"

/**
 * WSConnectionFailed exception.
 */
class WSConnectionFailed : public AosException {
public:
    /**
     * Creates WSConnectionFailed exception instance.
     *
     * @param message exception message.
     * @param err Aos error.
     */
    explicit WSConnectionFailed(const std::string& message, const aos::Error& err = aos::ErrorEnum::eFailed)
        : AosException(message, err) {};
};

/**
 * WSNoConnectionError exception.
 */
class WSNoConnectionError : public AosException {
public:
    /**
     * Creates WSNoConnectionError exception instance.
     *
     * @param message exception message.
     * @param err Aos error.
     */
    explicit WSNoConnectionError(const std::string& message, const aos::Error& err = aos::ErrorEnum::eFailed)
        : AosException(message, err) {};
};

/**
 * WSSendFrameError exception.
 */
class WSSendFrameError : public AosException {
public:
    /**
     * Creates WSSendFrameError exception instance.
     *
     * @param message exception message.
     * @param err Aos error.
     */
    explicit WSSendFrameError(const std::string& message, const aos::Error& err = aos::ErrorEnum::eFailed)
        : AosException(message, err) {};
};

#endif
