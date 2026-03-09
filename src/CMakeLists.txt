# SPDX-License-Identifier: GPL-2.0-only
#
# src/CMakeLists.txt - Kernel module build configuration
#
# Note: Kernel modules use the kernel build system (kbuild), not standard CMake.
# This CMake file provides integration and convenience targets.
#

set(MODULE_NAME dattobd)
set(MODULE_SOURCES
    bdev_state_handler.c
    bio_helper.c
    bio_list.c
    bio_queue.c
    blkdev.c
    callback_refs.c
    cow_manager.c
    filesystem.c
    ftrace_hooking.c
    kretprobe_hooking.c
    module_control.c
    module_threads.c
    mrf.c
    netlink_handlers.c
    paging_helper.c
    proc_seq_file.c
    snap_device.c
    snap_handle.c
    snap_ops.c
    sset_list.c
    sset_queue.c
    submit_bio.c
    task_helper.c
    tracer.c
    tracer_helper.c
    tracing_params.c
    userspace_copy_helpers.c
)

set(MODULE_HEADERS
    bdev_state_handler.h
    bio_helper.h
    bio_list.h
    bio_queue.h
    bio_request_callback.h
    blkdev.h
    callback_refs.h
    config.h
    cow_manager.h
    dattobd.h
    filesystem.h
    ftrace_hooking.h
    hints.h
    includes.h
    kernel_hooking.h
    kretprobe_hooking.h
    logging.h
    module_control.h
    module_threads.h
    mrf.h
    netlink_handlers.h
    paging_helper.h
    proc_seq_file.h
    snap_device.h
    snap_handle.h
    snap_ops.h
    sset_list.h
    sset_queue.h
    submit_bio.h
    task_helper.h
    tracer.h
    tracer_helper.h
    tracing_params.h
    userspace_copy_helpers.h
)

find_program(MAKE_EXECUTABLE make REQUIRED)
find_program(GENCONFIG_SCRIPT genconfig.sh HINTS ${CMAKE_CURRENT_SOURCE_DIR})

set(KERNEL_BUILD_DIR ${KERNEL_SOURCE_DIR})
set(MODULE_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(FEATURE_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/configure-tests/feature-tests/build)

add_custom_command(
    OUTPUT ${MODULE_BUILD_DIR}/kernel-config.h
    COMMAND ${CMAKE_COMMAND} -E make_directory ${FEATURE_TEST_DIR}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/genconfig.sh ${KERNEL_VERSION} ""
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${MODULE_SOURCES} ${MODULE_HEADERS}
    COMMENT "Generating kernel configuration for ${KERNEL_VERSION}"
    VERBATIM
)

add_custom_target(kernel-config
    DEPENDS ${MODULE_BUILD_DIR}/kernel-config.h
)

add_custom_command(
    OUTPUT ${MODULE_BUILD_DIR}/${MODULE_NAME}.ko
    COMMAND ${MAKE_EXECUTABLE} -C ${KERNEL_BUILD_DIR}
        M=${CMAKE_CURRENT_SOURCE_DIR}
        modules
    DEPENDS ${MODULE_SOURCES} ${MODULE_HEADERS} kernel-config
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building kernel module ${MODULE_NAME}.ko for kernel ${KERNEL_VERSION}"
    VERBATIM
)

add_custom_target(driver ALL
    DEPENDS ${MODULE_BUILD_DIR}/${MODULE_NAME}.ko
)

add_custom_target(driver-clean
    COMMAND ${MAKE_EXECUTABLE} -C ${KERNEL_BUILD_DIR}
        M=${CMAKE_CURRENT_SOURCE_DIR}
        clean
    COMMAND ${CMAKE_COMMAND} -E remove -f kernel-config.h
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${FEATURE_TEST_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Cleaning kernel module build"
)

add_custom_target(driver-install
    COMMAND ${MAKE_EXECUTABLE} -C ${KERNEL_BUILD_DIR}
        M=${CMAKE_CURRENT_SOURCE_DIR}
        modules_install
    DEPENDS driver
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Installing kernel module to /lib/modules/${KERNEL_VERSION}"
)

add_custom_target(driver-uninstall
    COMMAND ${CMAKE_COMMAND} -E remove -f
        /lib/modules/${KERNEL_VERSION}/extra/${MODULE_NAME}.ko
    COMMENT "Uninstalling kernel module from /lib/modules/${KERNEL_VERSION}"
)

set_target_properties(driver PROPERTIES
    OUTPUT_NAME ${MODULE_NAME}.ko
)

install(CODE "
    execute_process(
        COMMAND ${MAKE_EXECUTABLE} -C ${KERNEL_BUILD_DIR}
            M=${CMAKE_CURRENT_SOURCE_DIR}
            modules_install
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
")

message(STATUS "Kernel module: ${MODULE_NAME}.ko")
message(STATUS "Kernel build dir: ${KERNEL_BUILD_DIR}")
