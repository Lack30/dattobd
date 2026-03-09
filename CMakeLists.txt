# SPDX-License-Identifier: GPL-2.0-only
#
# CMakeLists.txt - Datto Block Driver Build Configuration
#
cmake_minimum_required(VERSION 3.16)

project(dattobd
    VERSION 0.12.0
    LANGUAGES C
    DESCRIPTION "Datto Block Driver - Linux kernel module for block device snapshots"
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BUILD_DRIVER "Build kernel module (driver)" ON)
option(BUILD_LIBRARY "Build user-space library" ON)
option(BUILD_APPLICATION "Build CLI application (dbdctl)" ON)
option(BUILD_UTILS "Build utility tools (update-img)" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_STATIC_LIBS "Build static library" ON)
option(INSTALL_HEADERS "Install header files" ON)

set(KERNEL_VERSION "" CACHE STRING "Kernel version to build for (empty for current)")
set(KERNEL_SOURCE_DIR "" CACHE PATH "Path to kernel source directory")

if(NOT KERNEL_VERSION)
    execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if(NOT KERNEL_SOURCE_DIR)
    set(KERNEL_SOURCE_DIR "/lib/modules/${KERNEL_VERSION}/build")
endif()

message(STATUS "==============================================")
message(STATUS "Datto Block Driver v${PROJECT_VERSION}")
message(STATUS "==============================================")
message(STATUS "Kernel version: ${KERNEL_VERSION}")
message(STATUS "Kernel source:  ${KERNEL_SOURCE_DIR}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  BUILD_DRIVER:     ${BUILD_DRIVER}")
message(STATUS "  BUILD_LIBRARY:    ${BUILD_LIBRARY}")
message(STATUS "  BUILD_APPLICATION:${BUILD_APPLICATION}")
message(STATUS "  BUILD_UTILS:      ${BUILD_UTILS}")
message(STATUS "  BUILD_SHARED_LIBS:${BUILD_SHARED_LIBS}")
message(STATUS "  BUILD_STATIC_LIBS:${BUILD_STATIC_LIBS}")
message(STATUS "==============================================")

set(DATTOBD_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_subdirectory(lib)

if(BUILD_APPLICATION)
    add_subdirectory(app)
endif()

if(BUILD_UTILS)
    add_subdirectory(utils)
endif()

if(BUILD_DRIVER)
    add_subdirectory(src)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/dattobdConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/dattobdConfig.cmake
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/dattobdConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dattobd
)

if(INSTALL_HEADERS)
    install(FILES
        ${DATTOBD_INCLUDE_DIR}/dattobd.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

set(CPACK_PACKAGE_NAME "dattobd")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Datto Block Driver")
set(CPACK_PACKAGE_LICENSE "GPL-2.0-only")
set(CPACK_PACKAGE_CONTACT "Datto Inc.")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "linux-headers-${KERNEL_VERSION}")
set(CPACK_RPM_PACKAGE_REQUIRES "kernel-devel-${KERNEL_VERSION}")

include(CPack)
