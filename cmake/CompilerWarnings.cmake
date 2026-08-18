# papa_set_compiler_warnings(<target>) -- attaches warning flags

set(PAPA_MSVC_WARNINGS
    /W4
    /permissive-
    /w14242 /w14254 /w14263 /w14265 /w14287
    /we4289
    /w14296 /w14311
    /w14545 /w14546 /w14547 /w14549 /w14555
    /w14619 /w14640
    /w14826 /w14905 /w14906 /w14928
)

set(PAPA_CLANG_WARNINGS
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wcast-align
    -Wunused
    # Off because every aggregate in the tree either gives its members default
    # initializers or is value-initialized with {}, so naming only the leading
    # members still leaves the rest fully defined. The warning reports that safe
    # omission, and padding each site with {} to silence it reads worse
    -Wno-missing-field-initializers
    -Woverloaded-virtual
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-fallthrough
)

set(PAPA_GCC_WARNINGS
    ${PAPA_CLANG_WARNINGS}
    -Wmisleading-indentation
    -Wduplicated-cond
    -Wduplicated-branches
    -Wlogical-op
    # -Wuseless-cast is deliberately not here. Whether a width cast is redundant
    # depends on the data model, so it contradicts -Wconversion in portable
    # code: narrowing a std::uint64_t to a std::size_t needs a cast on a 32-bit
    # target and -Wconversion demands one, while on LP64 the two are the same
    # type and -Wuseless-cast rejects the very same cast. No single spelling
    # satisfies both, and the defensive cast is the safer of the two
)

function(papa_set_compiler_warnings TARGET)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set(WARNINGS ${PAPA_MSVC_WARNINGS})
    elseif(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
        set(WARNINGS ${PAPA_CLANG_WARNINGS})
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(WARNINGS ${PAPA_GCC_WARNINGS})
    else()
        message(AUTHOR_WARNING "unknown compiler '${CMAKE_CXX_COMPILER_ID}'")
        set(WARNINGS "")
    endif()

    if(PAPA_WARNINGS_AS_ERRORS)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
            list(APPEND WARNINGS /WX)
        else()
            list(APPEND WARNINGS -Werror)
        endif()
    endif()

    target_compile_options(${TARGET} INTERFACE ${WARNINGS})
endfunction()
