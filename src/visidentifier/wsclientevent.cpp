/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wsclientevent.hpp"

std::pair<WSClientEvent::EventEnum, std::string> WSClientEvent::Wait()
{
    // blocking wait
    mEvent.wait();
    return mDetails;
}

void WSClientEvent::Set(const EventEnum code, const std::string& message)
{
    mDetails.first  = code;
    mDetails.second = message;
    mEvent.set();
}

void WSClientEvent::Reset()
{
    mEvent.reset();
}
