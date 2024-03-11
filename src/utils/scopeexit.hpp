/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SCOPE_EXIT_HPP_
#define SCOPE_EXIT_HPP_

#include <functional>

/**
 * Scope Exit.
 */
class ScopeExit {
public:
    /**
     * Creates Scope Exit instance.
     *
     * @param func functor.
     */
    ScopeExit(std::function<void()> func)
        : mFunctor(std::move(func))
    {
    }

    /**
     * Destructs Scope Exit instance.
     *
     */
    ~ScopeExit() noexcept { mFunctor(); }

private:
    std::function<void()> mFunctor;
};

#endif
