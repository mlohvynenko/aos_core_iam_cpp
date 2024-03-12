/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WS_CLIENT_EVENT_HPP_
#define WS_CLIENT_EVENT_HPP_

#include <Poco/Event.h>
#include <string>

/**
 * Web socket client event.
 */
class WSClientEvent {
public:
    /**
     * Web socket client event enum.
     */
    enum class EventEnum { CLOSED, FAILED };

    /**
     * Waits for event is to be set.
     *
     * @returns std::pair<EventEnum, std::string>
     */
    std::pair<EventEnum, std::string> Wait();

    /**
     * Sets event with the passed details.
     *
     * @param code event enum value
     * @param message event message
     * @returns std::pair<EventEnum, std::string>
     */
    void Set(const EventEnum code, const std::string& message);

    /**
     * Resets event.
     */
    void Reset();

private:
    Poco::Event                       mEvent;
    std::pair<EventEnum, std::string> mDetails;
};

#endif
