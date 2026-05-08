# unit tests -- one executable, shared doctest main

set(PAPA_UNIT_TEST_SOURCES
    test_main.cpp
    test_version.cpp
    test_pe_parser.cpp
    test_disassembler.cpp
    test_cfg.cpp
    test_address.cpp
    test_feature_semantics.cpp
    test_engine.cpp
    test_yaml_parser.cpp
    test_rules_parser.cpp
    test_ruleset.cpp
    test_com_lookup.cpp
    test_string_utils.cpp
    test_extractor_helpers.cpp
    test_strings_extractor.cpp
    test_global_extractor.cpp
    test_pefile_extractor.cpp
    test_insn_extractor.cpp
    test_bb_function_extractors.cpp
    test_backend.cpp
    test_capabilities.cpp
    test_hash.cpp
    test_json_writer.cpp
    test_render.cpp
    test_library_signatures.cpp
)

add_executable(papa_unit_tests ${PAPA_UNIT_TEST_SOURCES})

target_link_libraries(papa_unit_tests
    PRIVATE
        papa::lib
        doctest::doctest
        papa_project_options
)

add_test(NAME papa_unit_tests COMMAND papa_unit_tests)

# Phase 1 acceptance: `papa --version` prints a non-empty banner
add_test(
    NAME papa_cli_version
    COMMAND papa_cli --version
)
set_tests_properties(papa_cli_version PROPERTIES
    PASS_REGULAR_EXPRESSION "PAPA [0-9]+\\.[0-9]+\\.[0-9]+"
)
