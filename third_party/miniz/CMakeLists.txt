# miniz 3.0.2 amalgamation, used internally by the FLIRT reader for
# DEFLATE decompression of .sig bodies. Built as a small static library
# with the compress/archive/zlib-compat surfaces disabled — we only
# need the inflate path.

add_library(miniz STATIC miniz.c)

target_include_directories(miniz SYSTEM PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

set_target_properties(miniz PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_compile_definitions(miniz PRIVATE
    MINIZ_NO_STDIO
    MINIZ_NO_TIME
    MINIZ_NO_DEFLATE_APIS
    MINIZ_NO_ARCHIVE_APIS
    MINIZ_NO_ZLIB_APIS
    MINIZ_NO_ZLIB_COMPATIBLE_NAMES
)

if(MSVC)
    # The runtime is not selected here. CMAKE_MSVC_RUNTIME_LIBRARY (set from
    # PAPA_STATIC_RUNTIME in the root CMakeLists, under policy CMP0091) drives
    # every target, so this archive always matches the one papa_lib links.
    # Hardcoding /MD here silently mixed the dynamic and static CRTs, which the
    # linker only reports as the easily-missed warning LNK4098.
    target_compile_options(miniz PRIVATE /W0)
else()
    target_compile_options(miniz PRIVATE -w)
endif()

add_library(miniz::miniz ALIAS miniz)
