add_executable(replay_cli replay_cli.cpp)
target_link_libraries(replay_cli PRIVATE pcapreplay_common pcapreplay_nmos)
# For resource.h, purely so the CLI banner reads the same version constant the
# GUI and VERSIONINFO do rather than carrying a second copy to forget to bump.
target_include_directories(replay_cli PRIVATE "${CMAKE_SOURCE_DIR}/app")
