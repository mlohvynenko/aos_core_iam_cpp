/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LOG_HPP_
#define LOG_HPP_

#include <logger/logger.hpp>

#define LOG_DBG() LOG_MODULE_DBG(AosLogModule(::LogModuleEnum::eUtils))
#define LOG_INF() LOG_MODULE_INF(AosLogModule(::LogModuleEnum::eUtils))
#define LOG_WRN() LOG_MODULE_WRN(AosLogModule(::LogModuleEnum::eUtils))
#define LOG_ERR() LOG_MODULE_ERR(AosLogModule(::LogModuleEnum::eUtils))

#endif