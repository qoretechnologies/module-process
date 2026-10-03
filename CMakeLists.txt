cmake_minimum_required(VERSION 3.8...3.31)

project(qore-process-module)

# internal copy of boost was prepared as seen in 3rd_party README file
option(USE_INTERNAL_BOOST "Enforce using internal copy of boost libraries" OFF)
option(USE_SYSTEM_BOOST_DEPENDENCIES
    "Use system Boost dependencies with the patched internal Boost.Process" OFF)

set (VERSION_MAJOR 2)
set (VERSION_MINOR 2)
set (VERSION_PATCH 0)

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake )

find_package(Qore 2.0 REQUIRED)

add_compile_options(-fPIC)
if(USE_SYSTEM_BOOST_DEPENDENCIES)
    if(USE_INTERNAL_BOOST)
        message(FATAL_ERROR "USE_SYSTEM_BOOST_DEPENDENCIES conflicts with USE_INTERNAL_BOOST")
    endif()
    # Boost.Process carries correctness fixes that are not in upstream 1.90.0.
    # Keep that implementation while using distribution headers and libraries
    # for its dependencies. An exact version prevents mixing Boost releases.
    find_package(Boost 1.90.0 EXACT CONFIG REQUIRED COMPONENTS filesystem)
    # Distribution BoostConfig packages export the header-only components as
    # Boost::headers. Boost.Process's own CMake file names them individually.
    foreach(component algorithm asio config core fusion iterator move optional
            system tokenizer type_index winapi)
        if(NOT TARGET Boost::${component})
            add_library(Boost::${component} INTERFACE IMPORTED)
            set_target_properties(Boost::${component} PROPERTIES
                INTERFACE_LINK_LIBRARIES Boost::headers)
        endif()
    endforeach()
    function(qore_process_add_patched_boost)
        # This library is private to the module and must not need installation.
        set(BUILD_SHARED_LIBS OFF)
        set(BOOST_SUPERPROJECT_VERSION 1.90.0)
        add_subdirectory(3rd_party/boost/libs/process)
    endfunction()
    qore_process_add_patched_boost()
else()
    set(BOOST_INCLUDE_LIBRARIES "filesystem;system;process")
    add_subdirectory(3rd_party/boost)
endif()

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
if(COMPILER_SUPPORTS_CXX17)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support; please use a different C++ compiler")
endif()

include(CheckCXXSymbolExists)
check_cxx_symbol_exists(kill signal.h HAVE_KILL)

include(CheckIncludeFiles)
check_include_files("sys/types.h;sys/loadavg.h" HAVE_SYS_LOADAVG_H)

set(CPP_SRC
    src/processpriv.cpp
)

#include_directories(
#    ${CMAKE_SOURCE_DIR}/3rd_party/boost/libs/process/include/boost/process/v1
#)

set(QPP_SRC
    src/process.qpp
    src/QC_Process.qpp
)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
)

if (WIN32)
    add_definitions(-DWINDOWS_API)
    set(WIN_LIBS wsock32 ws2_32)
endif (WIN32)

if (CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    set(SUNOS_LIBS proc)
endif (CMAKE_SYSTEM_NAME STREQUAL "SunOS")

qore_wrap_qpp_value(QPP_SOURCES DOXLIST QPP_DOX_SOURCES METALIST QPP_META_SRC ${QPP_SRC})

SET (module_name "process")

add_library(${module_name} MODULE ${CPP_SRC} ${QPP_SOURCES})

configure_file(${CMAKE_SOURCE_DIR}/cmake/unix-config.h.cmake
${CMAKE_BINARY_DIR}/unix-config.h)

if (DEFINED ENV{DOXYGEN_EXECUTABLE})
    set(DOXYGEN_EXECUTABLE $ENV{DOXYGEN_EXECUTABLE})
endif()

# Document the main page and the Qore declarations, excluding private implementation bodies.
set(QORE_DOX_TMPL_SRC
    docs/mainpage.dox.tmpl
    docs/guide-process_license.dox.tmpl
    docs/guide-process_platforms.dox.tmpl
    docs/guide-process_relnotes.dox.tmpl
)
set(MODULE_DOX_INPUT ${CMAKE_BINARY_DIR}/mainpage.dox ${QPP_DOX_SOURCES})

list(APPEND MODULE_DOX_INPUT
    ${CMAKE_CURRENT_BINARY_DIR}/guide-process_license.dox
    ${CMAKE_CURRENT_BINARY_DIR}/guide-process_platforms.dox
    ${CMAKE_CURRENT_BINARY_DIR}/guide-process_relnotes.dox
)
qore_external_binary_module(
    ${module_name}
    "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(${module_name} PRIVATE Boost::process proc)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "DragonFly"
       OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(${module_name} PRIVATE Boost::process kvm)
else()
    target_link_libraries(${module_name} PRIVATE Boost::process)
endif()
# dlsym() for Process::releaseFreeMemory()
target_link_libraries(${module_name} PRIVATE ${CMAKE_DL_LIBS} ${WIN_LIBS} ${SUNOS_LIBS})

qore_dist("${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

# install qpp metadata files
if (COMMAND qore_install_qpp_metadata)
    qore_install_qpp_metadata(${module_name} ${QPP_META_SRC})
else()
    install(FILES ${QPP_META_SRC}
            DESTINATION ${CMAKE_INSTALL_DATADIR}/qore/metadata)
endif()

qore_config_info()

if (DOXYGEN_FOUND)
  qore_wrap_dox(QORE_DOX_SRC ${QORE_DOX_TMPL_SRC})
  add_custom_target(QORE_MOD_DOX_FILES DEPENDS ${QORE_DOX_SRC})
  add_dependencies(docs-module QORE_MOD_DOX_FILES)
endif()
