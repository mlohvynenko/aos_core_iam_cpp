#
# Copyright (C) 2024 Renesas Electronics Corporation.
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET iamclient)

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES certhelper.cpp iamclient.cpp)

# ######################################################################################################################
# Target
# ######################################################################################################################

add_library(${TARGET} STATIC ${SOURCES})

# ######################################################################################################################
# Libraries
# ######################################################################################################################

target_link_libraries(
    ${TARGET}
    PUBLIC logger
           aoscommon
           aosiam
           aoscoreapi-gen-objects
           utils
           Poco::Util
           Poco::JSON
           mbedcrypto
           mbedx509
           mbedtls
           ${JOURNALD_LIBRARIES}
)

add_executable(client main.cpp)
target_link_libraries(client iamclient iamserver)
