# papa_set_hardening(<target>) -- stack protector, CFG/CET, _FORTIFY_SOURCE

function(papa_set_hardening TARGET)
    if(NOT PAPA_ENABLE_HARDENING)
        return()
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(${TARGET} INTERFACE
            /GS
            /guard:cf
            /Qspectre
            /sdl
        )
        target_link_options(${TARGET} INTERFACE
            /DYNAMICBASE
            /NXCOMPAT
            /HIGHENTROPYVA
            /guard:cf
            # Shadow-stack enforcement of returns on CET hardware, the return
            # side of the control-flow guarantee /guard:cf gives to indirect
            # calls. Ignored by CPUs without it, so it costs nothing elsewhere
            /CETCOMPAT
            # Every parser in the tree recurses over sample-derived structure.
            # Each one is depth-bounded, but the bounds multiply through nested
            # parsers, so the default 1 MB reserve is the thinnest margin in the
            # process. Reserving 8 MB does not commit the pages
            /STACK:8388608
        )
    elseif(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # _FORTIFY_SOURCE requires optimization so skip Debug
        target_compile_definitions(${TARGET} INTERFACE
            $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
        )
        target_compile_options(${TARGET} INTERFACE
            -fstack-protector-strong
            -fno-strict-aliasing
            -fno-strict-overflow
        )

        include(CheckCXXCompilerFlag)
        check_cxx_compiler_flag("-fcf-protection=full" PAPA_HAS_CF_PROTECTION)
        if(PAPA_HAS_CF_PROTECTION)
            target_compile_options(${TARGET} INTERFACE -fcf-protection=full)
        endif()

        check_cxx_compiler_flag("-fstack-clash-protection" PAPA_HAS_STACK_CLASH)
        if(PAPA_HAS_STACK_CLASH)
            target_compile_options(${TARGET} INTERFACE -fstack-clash-protection)
        endif()
    endif()
endfunction()
