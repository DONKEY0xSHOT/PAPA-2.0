# Two test buckets:
#   unit/        - doctest-based per-module C++ tests
#   integration/ - python harness that diffs papa.exe vs capa.exe on real PEs

add_subdirectory(unit)
add_subdirectory(integration)
