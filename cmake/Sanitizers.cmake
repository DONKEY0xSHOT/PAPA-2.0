# papa_set_sanitizers(<target>) -- Debug-only ASan/UBSan via PAPA_ENABLE_SANITIZERS

function(papa_set_sanitizers TARGET)
    if(NOT PAPA_ENABLE_SANITIZERS)
        return()
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${TARGET} INTERFACE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined -fno-omit-frame-pointer>
        )
        target_link_options(${TARGET} INTERFACE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        )
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        # MSVC 19.29+ has /fsanitize=address; no UBSan
        target_compile_options(${TARGET} INTERFACE
            $<$<CONFIG:Debug>:/fsanitize=address>
        )
    endif()
endfunction()
