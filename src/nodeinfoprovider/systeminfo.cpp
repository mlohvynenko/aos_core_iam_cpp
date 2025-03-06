/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fstream>
#include <sys/statfs.h>
#include <unordered_map>
#include <vector>

#include <utils/exception.hpp>
#include <utils/parser.hpp>

#include "logger/logmodule.hpp"
#include "systeminfo.hpp"

namespace aos::iam::nodeinfoprovider::utils {

namespace {

/***********************************************************************************************************************
 * Constants
 **********************************************************************************************************************/

constexpr auto cBytesPerKB = 1024;

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

class CPUInfoParser {
public:
    Error GetCPUInfo(const std::string& path, Array<CPUInfo>& cpuInfoArray)
    {
        if (mFile.open(path); !mFile.is_open()) {
            return ErrorEnum::eNotFound;
        }

        if (const auto err = ParseCPUInfoFile(); !err.IsNone()) {
            return err;
        }

        for (const auto& item : mCPUInfos) {
            if (const auto err = cpuInfoArray.PushBack(item.second); !err.IsNone()) {
                return err;
            }
        }

        return ErrorEnum::eNone;
    }

private:
    void PopulateCPUInfoObject()
    {
        if (mCurrentEntryKeyValues.empty()) {
            return;
        }

        size_t  physicalId = 0;
        CPUInfo cpuInfo;

        for (const auto& keyValue : mCurrentEntryKeyValues) {
            try {
                if (keyValue.mKey == "physical id") {
                    physicalId = std::stoul(keyValue.mValue);
                } else if (keyValue.mKey == "model name") {
                    cpuInfo.mModelName = keyValue.mValue.c_str();
                } else if (keyValue.mKey == "cpu cores") {
                    cpuInfo.mNumCores = std::stoul(keyValue.mValue);
                } else if (keyValue.mKey == "siblings") {
                    cpuInfo.mNumThreads = std::stoul(keyValue.mValue);
                } else if (keyValue.mKey == "cpu family") {
                    cpuInfo.mArch = keyValue.mValue.c_str();
                }
            } catch (...) {
                LOG_DBG() << "CPU info parsing failed: key=" << keyValue.mKey.c_str()
                          << ", value=" << keyValue.mValue.c_str();

                throw common::utils::AosException("Failed to parse CPU info", ErrorEnum::eFailed);
            }
        }

        // only the first entry for the CPU is stored in the map.
        mCPUInfos.insert({physicalId, cpuInfo});

        mCurrentEntryKeyValues.clear();
    }

    Error ParseCPUInfoFile() noexcept
    {
        try {
            std::string line;

            while (std::getline(mFile, line)) {
                const auto keyValue = common::utils::ParseKeyValue(line);

                if (!keyValue.has_value() || keyValue->mKey == "processor") {
                    PopulateCPUInfoObject();
                }

                if (keyValue.has_value()) {
                    mCurrentEntryKeyValues.push_back(std::move(keyValue.value()));
                }
            }

            // populate last CPU info object
            PopulateCPUInfoObject();
        } catch (const std::exception& e) {
            return common::utils::ToAosError(e);
        }

        return ErrorEnum::eNone;
    }

    std::ifstream                        mFile;
    std::unordered_map<size_t, CPUInfo>  mCPUInfos;
    std::vector<common::utils::KeyValue> mCurrentEntryKeyValues;
};

} // namespace

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error GetCPUInfo(const std::string& path, Array<CPUInfo>& cpuInfoArray) noexcept
{
    try {
        CPUInfoParser parser;

        return parser.GetCPUInfo(path, cpuInfoArray);
    } catch (const std::exception& e) {
        return common::utils::ToAosError(e);
    }
}

RetWithError<uint64_t> GetMemTotal(const std::string& path) noexcept
{
    try {
        std::ifstream file;

        if (file.open(path); !file.is_open()) {
            return {0, ErrorEnum::eNotFound};
        }

        std::string line;

        while (std::getline(file, line)) {
            const auto keyValue = common::utils::ParseKeyValue(line);

            if (!keyValue.has_value() || keyValue->mKey != "MemTotal") {
                continue;
            }

            const auto memTotalKB = std::stoull(keyValue->mValue.substr(0, keyValue->mValue.find(" ")));

            // convert KB to bytes
            return {memTotalKB * cBytesPerKB, ErrorEnum::eNone};
        }

    } catch (const std::exception& e) {
        return {0, AOS_ERROR_WRAP(common::utils::ToAosError(e))};
    }

    return {0, ErrorEnum::eFailed};
}

RetWithError<uint64_t> GetMountFSTotalSize(const std::string& path) noexcept
{
    struct statfs stat { };

    if (statfs(path.c_str(), &stat) == -1) {
        return {0, ErrorEnum::eFailed};
    }

    return {stat.f_blocks * stat.f_bsize, ErrorEnum::eNone};
}

} // namespace aos::iam::nodeinfoprovider::utils
