# SPDX-License-Identifier: LGPL-2.1-or-later
#
# lib/CMakeLists.txt - User-space library build configuration
#

set(LIB_SOURCES
    libdattobd.c
)

set(LIB_HEADERS
    libdattobd.h
    ${DATTOBD_INCLUDE_DIR}/dattobd.h
)

if(BUILD_SHARED_LIBS)
    add_library(dattobd SHARED ${LIB_SOURCES})
    target_include_directories(dattobd
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<BUILD_INTERFACE:${DATTOBD_INCLUDE_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    set_target_properties(dattobd PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        PUBLIC_HEADER libdattobd.h
    )
    target_link_libraries(dattobd PRIVATE ${CMAKE_DL_LIBS})
endif()

if(BUILD_STATIC_LIBS)
    add_library(dattobd_static STATIC ${LIB_SOURCES})
    target_include_directories(dattobd_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<BUILD_INTERFACE:${DATTOBD_INCLUDE_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    set_target_properties(dattobd_static PROPERTIES
        OUTPUT_NAME dattobd
        PUBLIC_HEADER libdattobd.h
    )
endif()

if(INSTALL_HEADERS)
    install(FILES ${LIB_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

if(BUILD_SHARED_LIBS)
    install(TARGETS dattobd
        EXPORT dattobdTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

if(BUILD_STATIC_LIBS)
    install(TARGETS dattobd_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

install(EXPORT dattobdTargets
    FILE dattobdTargets.cmake
    NAMESPACE dattobd::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dattobd
)
