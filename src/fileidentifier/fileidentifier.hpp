/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FILEIDENTIFIER_HPP_
#define FILEIDENTIFIER_HPP_

#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <Poco/Event.h>

#include <aos/iam/identhandler.hpp>

#include "config/config.hpp"

namespace aos::iam::fileidentifier {

/**
 * File Identifier.
 */
class FileIdentifier : public aos::iam::identhandler::IdentHandlerItf {
public:
    /**
     * Creates a new object instance.
     */
    FileIdentifier() = default;

    /**
     * Initializes vis identifier.
     *
     * @param config config object.
     * @param subjectsObserver subject observer.
     * @return Error.
     */
    Error Init(const config::Identifier& config, iam::identhandler::SubjectsObserverItf& subjectsObserver);

    /**
     * Returns System ID.
     *
     * @returns RetWithError<StaticString>.
     */
    RetWithError<StaticString<cSystemIDLen>> GetSystemID() override;

    /**
     * Returns unit model.
     *
     * @returns RetWithError<StaticString>.
     */
    RetWithError<StaticString<cUnitModelLen>> GetUnitModel() override;

    /**
     * Returns subjects.
     *
     * @param[out] subjects result subjects.
     * @returns Error.
     */
    Error GetSubjects(Array<StaticString<cSubjectIDLen>>& subjects) override;

    /**
     * Destroys vis identifier object instance.
     */
    ~FileIdentifier() override = default;

private:
    Error ReadSubjectsFromFile();

    config::FileIdentifierModuleParams                          mConfig;
    identhandler::SubjectsObserverItf*                          mSubjectsObserver = nullptr;
    StaticString<cSystemIDLen>                                  mSystemId;
    StaticString<cUnitModelLen>                                 mUnitModel;
    StaticArray<StaticString<cSubjectIDLen>, cMaxSubjectIDSize> mSubjects;
};

} // namespace aos::iam::fileidentifier

#endif
