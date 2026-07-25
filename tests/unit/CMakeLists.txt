# unit tests -- one executable, shared doctest main

set(PAPA_UNIT_TEST_SOURCES
    test_main.cpp
    test_version.cpp
    test_pe_parser.cpp
    test_disassembler.cpp
    test_cfg.cpp
    test_viv_location_db.cpp
    test_viv_xref_db.cpp
    test_viv_cf_context.cpp
    test_viv_codeblocks.cpp
    test_viv_discovery.cpp
    test_viv_discovery_passes.cpp
    test_viv_engine.cpp
    test_viv_flirt_analysis.cpp
    test_jump_tables.cpp
    test_noreturn.cpp
    test_address.cpp
    test_feature_semantics.cpp
    test_engine.cpp
    test_yaml_parser.cpp
    test_rules_parser.cpp
    test_ruleset.cpp
    test_optimizer.cpp
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
    test_render_table.cpp
    test_library_signatures.cpp
    test_flirt_format.cpp
    test_flirt_crc16.cpp
    test_flirt_decompress.cpp
    test_flirt_tree.cpp
    test_flirt_reader.cpp
    test_flirt_matcher.cpp
    test_flirt_classifier.cpp
    test_flirt_signature_set.cpp
    test_flirt_integration.cpp
    test_emu_registers.cpp
    test_emu_bits.cpp
    test_emu_memory.cpp
    test_emu_operands.cpp
    test_emu_arith.cpp
    test_emu_controlflow.cpp
    test_emu_branches.cpp
    test_emu_taints.cpp
    test_emu_workspace.cpp
    test_emu_watcher.cpp
    test_emu_discovery.cpp
    test_diag.cpp
)

add_executable(papa_unit_tests ${PAPA_UNIT_TEST_SOURCES})

target_link_libraries(papa_unit_tests
    PRIVATE
        papa::lib
        doctest::doctest
        papa_project_options
)

# The embedded-registry test locks the FLIRT resources from the running exe,
# so the unit-test binary must carry the same RCDATA resources as papa.exe.
if(MSVC)
    target_sources(papa_unit_tests PRIVATE
        "${CMAKE_SOURCE_DIR}/third_party/flirt_sigs/flirt_sigs.rc")
    set_source_files_properties(
        "${CMAKE_SOURCE_DIR}/third_party/flirt_sigs/flirt_sigs.rc"
        PROPERTIES COMPILE_OPTIONS
        "/I${CMAKE_SOURCE_DIR}/third_party/flirt_sigs")
endif()

add_test(NAME papa_unit_tests COMMAND papa_unit_tests)

# Phase 1 acceptance: `papa --version` prints a non-empty banner
add_test(
    NAME papa_cli_version
    COMMAND papa_cli --version
)
set_tests_properties(papa_cli_version PROPERTIES
    PASS_REGULAR_EXPRESSION "PAPA [0-9]+\\.[0-9]+\\.[0-9]+"
)
