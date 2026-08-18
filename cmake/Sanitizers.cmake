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
        # MSVC has ASan but no UBSan
        target_compile_options(${TARGET} INTERFACE
            $<$<CONFIG:Debug>:/fsanitize=address>
        )
        # CMake passes /fsanitize=address as a plain compile flag, so MSBuild
        # never learns ASan is on and leaves the runtime directory off the link
        get_filename_component(_papa_msvc_bin "${CMAKE_LINKER}" DIRECTORY)
        get_filename_component(_papa_msvc_root "${_papa_msvc_bin}/../../.." ABSOLUTE)
        set(_papa_asan_libs "${_papa_msvc_root}/lib/${CMAKE_VS_PLATFORM_NAME}")
        if(EXISTS "${_papa_asan_libs}")
            target_link_directories(${TARGET} INTERFACE
                $<$<CONFIG:Debug>:${_papa_asan_libs}>
            )
        endif()
        # Incremental linking is incompatible with ASan metadata
        target_link_options(${TARGET} INTERFACE
            $<$<CONFIG:Debug>:/INCREMENTAL:NO>
        )
    endif()
endfunction()
