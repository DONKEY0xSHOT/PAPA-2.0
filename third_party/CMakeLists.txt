# third-party deps

# doctest: single-header, no binary
add_library(doctest INTERFACE)
add_library(doctest::doctest ALIAS doctest)
target_include_directories(doctest INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/doctest"
)

# Zydis: vendored subdir, trim to just the decoder we need
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN  OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN      OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)

add_subdirectory(zydis EXCLUDE_FROM_ALL)

# Zydis headers are C, treat as SYSTEM so our -W... flags do not fire on them
if (TARGET Zydis)
    get_target_property(_zydis_inc Zydis INTERFACE_INCLUDE_DIRECTORIES)
    if (_zydis_inc)
        set_target_properties(Zydis PROPERTIES
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_zydis_inc}")
    endif()
endif()
if (TARGET Zycore)
    get_target_property(_zycore_inc Zycore INTERFACE_INCLUDE_DIRECTORIES)
    if (_zycore_inc)
        set_target_properties(Zycore PROPERTIES
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_zycore_inc}")
    endif()
endif()
