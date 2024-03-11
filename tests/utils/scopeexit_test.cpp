/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024s EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logger/logger.hpp"
#include "utils/scopeexit.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing;

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

class ScopeExitTest : public Test {
protected:
    MockFunction<void()> mMockFunction;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(ScopeExitTest, ExecutedOnScopeExit)
{
    EXPECT_CALL(mMockFunction, Call).Times(1);

    ScopeExit onExit {mMockFunction.AsStdFunction()};
}

TEST_F(ScopeExitTest, ExecutedOnExceptionHandling)
{
    try {
        EXPECT_CALL(mMockFunction, Call).Times(1);
        ScopeExit onExit {mMockFunction.AsStdFunction()};

        throw std::runtime_error("error");
    } catch (...) {
    };
}
