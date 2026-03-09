# SPDX-License-Identifier: GPL-2.0-only
#
# utils/CMakeLists.txt - Utility tools build configuration
#

set(UTILS_SOURCES
    update-img.c
)

add_executable(update-img ${UTILS_SOURCES})

target_include_directories(update-img PRIVATE
    ${DATTOBD_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)

target_compile_definitions(update-img PRIVATE
    _XOPEN_SOURCE=500
)

if(BUILD_SHARED_LIBS)
    target_link_libraries(update-img PRIVATE dattobd)
else()
    target_link_libraries(update-img PRIVATE dattobd_static)
endif()

install(TARGETS update-img
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
