# papa CLI binary

add_executable(papa_cli papa_main.cpp)

set_target_properties(papa_cli PROPERTIES
    OUTPUT_NAME "papa"
)

target_link_libraries(papa_cli
    PRIVATE
        papa::lib
        papa_project_options
)

papa_enable_lto(papa_cli)

# Embed the vendored FLIRT signatures as RCDATA. Resources live in the exe,
# not the static lib, because registry() locks them from the running module.
if(MSVC)
    target_sources(papa_cli PRIVATE
        "${CMAKE_SOURCE_DIR}/third_party/flirt_sigs/flirt_sigs.rc")
    set_source_files_properties(
        "${CMAKE_SOURCE_DIR}/third_party/flirt_sigs/flirt_sigs.rc"
        PROPERTIES COMPILE_OPTIONS
        "/I${CMAKE_SOURCE_DIR}/third_party/flirt_sigs")
endif()
