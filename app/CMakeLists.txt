# SPDX-License-Identifier: GPL-2.0-only
#
# app/CMakeLists.txt - CLI application build configuration
#

set(APP_SOURCES
    dbdctl.c
)

add_executable(dbdctl ${APP_SOURCES})

target_include_directories(dbdctl PRIVATE
    ${DATTOBD_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)

if(BUILD_SHARED_LIBS)
    target_link_libraries(dbdctl PRIVATE dattobd)
else()
    target_link_libraries(dbdctl PRIVATE dattobd_static)
endif()

install(TARGETS dbdctl
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/bash_completion.d/dbdctl
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions
    RENAME dbdctl
)
