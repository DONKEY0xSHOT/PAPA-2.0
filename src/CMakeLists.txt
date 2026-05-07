# papa_lib -- core static library; phases append to PAPA_LIB_SOURCES

set(PAPA_LIB_SOURCES
    version.cpp
    exceptions.cpp
    engine.cpp
    pe/pe_image.cpp
    pe/pe_parser.cpp
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
    features/extractors/papa_native/global_.cpp
    features/extractors/papa_native/insn.cpp
    features/extractors/papa_native/indirect_calls.cpp
    features/extractors/papa_native/basic_block.cpp
    features/extractors/papa_native/function.cpp
    features/extractors/papa_native/backend.cpp
    features/extractors/papa_native/extractor.cpp
    features/extractors/pefile_extractor.cpp
    capabilities/common.cpp
    capabilities/static_.cpp
    loader.cpp
    render/result_document.cpp
    render/json.cpp
    render/text.cpp
    main_driver.cpp
    util/yaml.cpp
    util/hash.cpp
    util/json_writer.cpp
    util/string_utils.cpp
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

target_link_libraries(papa_lib
    PUBLIC
        Zydis
    PRIVATE
        papa_project_options
)

set_target_properties(papa_lib PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
