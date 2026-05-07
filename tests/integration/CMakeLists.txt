# Parity harness: runs papa.exe and capa.exe on each test binary and compares
# the matched-rule sets. The Python harness is invoked through ctest so users
# can run "ctest -R papa_parity" alongside the unit tests.
#
# All paths default to empty so the repository carries no machine-specific
# locations. Three CMake cache variables, equivalent environment variables,
# or both must be set for the parity tests to run; otherwise the tests are
# registered as DISABLED and ctest skips them cleanly.
#
#   PAPA_PARITY_CAPA_EXE     path to capa.exe used as the parity baseline
#   PAPA_PARITY_RULES_DIR    path to the capa-rules corpus
#   PAPA_PARITY_FIXTURES     directory containing the sample PE binaries

set(PAPA_PARITY_CAPA_EXE   "$ENV{PAPA_PARITY_CAPA_EXE}"
    CACHE FILEPATH "Path to capa.exe used as the parity baseline")
set(PAPA_PARITY_RULES_DIR  "$ENV{PAPA_PARITY_RULES_DIR}"
    CACHE PATH     "Path to the capa-rules corpus shared by both tools")
set(PAPA_PARITY_FIXTURES   "$ENV{PAPA_PARITY_FIXTURES}"
    CACHE PATH     "Directory containing the test sample binaries")

find_package(Python3 COMPONENTS Interpreter)

# One ctest entry per fixture so failures isolate to a single sample
set(PAPA_PARITY_SAMPLES
    notepad.exe
    "CFF Explorer.exe"
    capa.exe
    chrome.exe
)

set(_papa_parity_ready FALSE)
if(Python3_Interpreter_FOUND
   AND PAPA_PARITY_CAPA_EXE
   AND PAPA_PARITY_RULES_DIR
   AND PAPA_PARITY_FIXTURES
   AND EXISTS "${PAPA_PARITY_CAPA_EXE}"
   AND EXISTS "${PAPA_PARITY_RULES_DIR}"
   AND EXISTS "${PAPA_PARITY_FIXTURES}")
    set(_papa_parity_ready TRUE)
endif()

foreach(sample IN LISTS PAPA_PARITY_SAMPLES)
    string(REPLACE " " "_" safe "${sample}")
    string(REPLACE "." "_" safe "${safe}")
    set(test_name "papa_parity_${safe}")
    if(_papa_parity_ready)
        add_test(
            NAME ${test_name}
            COMMAND ${Python3_EXECUTABLE}
                "${CMAKE_CURRENT_SOURCE_DIR}/run_parity.py"
                --papa   "$<TARGET_FILE:papa_cli>"
                --capa   "${PAPA_PARITY_CAPA_EXE}"
                --rules  "${PAPA_PARITY_RULES_DIR}"
                --sample "${PAPA_PARITY_FIXTURES}/${sample}"
        )
        # Allow up to 15 minutes per binary to accommodate chrome.exe
        set_tests_properties(${test_name} PROPERTIES TIMEOUT 900)
    else()
        add_test(NAME ${test_name} COMMAND ${CMAKE_COMMAND} -E echo
            "skipping parity (set PAPA_PARITY_CAPA_EXE, PAPA_PARITY_RULES_DIR, PAPA_PARITY_FIXTURES)")
        set_tests_properties(${test_name} PROPERTIES DISABLED TRUE)
    endif()
endforeach()
