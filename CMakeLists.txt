cmake_minimum_required(VERSION 3.24)
set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)

# Link the C and C++ runtimes statically
option(PAPA_STATIC_RUNTIME "Link the C/C++ runtime statically" ON)
if(PAPA_STATIC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

project(papa
    VERSION 0.1.0
    DESCRIPTION "C++ port of CAPA static PE capability detector"
    LANGUAGES CXX
)

cmake_policy(SET CMP0091 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "in-source builds are not permitted; use cmake -S . -B build")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING
        "Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

option(PAPA_BUILD_TESTS         "Build unit and integration tests"       ON)
option(PAPA_ENABLE_SANITIZERS   "Enable ASan/UBSan in Debug builds"      OFF)
option(PAPA_WARNINGS_AS_ERRORS  "Treat compiler warnings as errors"      ON)
option(PAPA_ENABLE_HARDENING    "Enable hardening compiler/linker flags" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Sanitizers)
include(Hardening)

# single INTERFACE target that every PAPA target privately links
add_library(papa_project_options INTERFACE)
papa_set_compiler_warnings(papa_project_options)
papa_set_sanitizers(papa_project_options)
papa_set_hardening(papa_project_options)

if(MSVC)
    target_compile_options(papa_project_options INTERFACE
        "/d1trimfile:${CMAKE_SOURCE_DIR}/")
else()
    target_compile_options(papa_project_options INTERFACE
        "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/="
        "-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=")
endif()

# The gcc/clang half of the static-runtime option. CMAKE_MSVC_RUNTIME_LIBRARY
# covers MSVC, and these carry the libstdc++ and libgcc equivalents
if(PAPA_STATIC_RUNTIME AND NOT MSVC)
    target_link_options(papa_project_options INTERFACE
        -static-libstdc++ -static-libgcc)
endif()

add_subdirectory(third_party)
add_subdirectory(src)
add_subdirectory(tools/papa)

if(PAPA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

message(STATUS "")
message(STATUS "PAPA configuration:")
message(STATUS "  Version            : ${PROJECT_VERSION}")
message(STATUS "  C++ standard       : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler           : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Tests              : ${PAPA_BUILD_TESTS}")
message(STATUS "  Sanitizers         : ${PAPA_ENABLE_SANITIZERS}")
message(STATUS "  Warnings as errors : ${PAPA_WARNINGS_AS_ERRORS}")
message(STATUS "  Hardening          : ${PAPA_ENABLE_HARDENING}")
message(STATUS "")
