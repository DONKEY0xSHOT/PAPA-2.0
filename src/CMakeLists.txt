# papa_lib -- core static library; phases append to PAPA_LIB_SOURCES

set(PAPA_LIB_SOURCES
    version.cpp
    exceptions.cpp
    engine.cpp
    pe/pe_image.cpp
    pe/pe_parser.cpp
    pe/ordinal_names.cpp
    rules/scope.cpp
    rules/rule.cpp
    features/address.cpp
    features/feature.cpp
    features/common.cpp
    features/file.cpp
    features/insn.cpp
    features/basic_block.cpp
    features/extractors/helpers.cpp
    features/extractors/strings.cpp
    features/extractors/pefile.cpp
    features/extractors/papa_native/disassembler.cpp
    features/extractors/papa_native/cfg.cpp
    features/extractors/papa_native/viv/location_db.cpp
    features/extractors/papa_native/viv/xref_db.cpp
    features/extractors/papa_native/viv/cf_context.cpp
    features/extractors/papa_native/viv/codeblocks.cpp
    features/extractors/papa_native/viv/discovery.cpp
    features/extractors/papa_native/viv/discovery_passes.cpp
    features/extractors/papa_native/viv/flirt_analysis.cpp
    features/extractors/papa_native/viv/engine.cpp
    features/extractors/papa_native/global_.cpp
    features/extractors/papa_native/insn.cpp
    features/extractors/papa_native/indirect_calls.cpp
    features/extractors/papa_native/jump_tables.cpp
    features/extractors/papa_native/noreturn.cpp
    features/extractors/papa_native/basic_block.cpp
    features/extractors/papa_native/function.cpp
    features/extractors/papa_native/backend.cpp
    features/extractors/papa_native/extractor.cpp
    features/extractors/papa_native/library_signatures.cpp
    features/extractors/papa_native/flirt/flirt_crc16.cpp
    features/extractors/papa_native/flirt/flirt_decompress.cpp
    features/extractors/papa_native/flirt/flirt_tree.cpp
    features/extractors/papa_native/flirt/flirt_reader.cpp
    features/extractors/papa_native/flirt/flirt_matcher.cpp
    features/extractors/papa_native/flirt/flirt_classifier.cpp
    features/extractors/papa_native/flirt/flirt.cpp
    features/extractors/papa_native/flirt/embedded_sigs.cpp
    features/extractors/papa_native/emu/registers.cpp
    features/extractors/papa_native/emu/memory.cpp
    features/extractors/papa_native/emu/intel_emulator.cpp
    features/extractors/papa_native/emu/taints.cpp
    features/extractors/papa_native/emu/workspace_emulator.cpp
    features/extractors/papa_native/emu/watcher.cpp
    features/extractors/papa_native/emu/emu_discovery.cpp
    features/extractors/pefile_extractor.cpp
    capabilities/common.cpp
    capabilities/static_.cpp
    loader.cpp
    render/result_document.cpp
    render/json.cpp
    render/spec.cpp
    render/table.cpp
    render/text.cpp
    main_driver.cpp
    util/yaml.cpp
    util/hash.cpp
    util/json_writer.cpp
    util/string_utils.cpp
    rules/optimizer.cpp
    rules/parser.cpp
    rules/ruleset.cpp
    rules/com_lookup.cpp
    rules/com_classes.cpp
    rules/com_interfaces.cpp
)

add_library(papa_lib STATIC ${PAPA_LIB_SOURCES})
add_library(papa::lib ALIAS papa_lib)

target_include_directories(papa_lib
    PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
)

# embedded_sigs.cpp includes the FLIRT resource id header on MSVC.
if(MSVC)
    target_include_directories(papa_lib
        PRIVATE
            "${CMAKE_SOURCE_DIR}/third_party/flirt_sigs"
    )
endif()

target_link_libraries(papa_lib
    PUBLIC
        Zydis
    PRIVATE
        papa_project_options
        miniz::miniz
)

set_target_properties(papa_lib PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
