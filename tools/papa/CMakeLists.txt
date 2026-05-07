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
