add_executable(replay_cli replay_cli.cpp)
target_link_libraries(replay_cli PRIVATE pcapreplay_common pcapreplay_nmos)
if(NOT WIN32)
    target_link_libraries(replay_cli PRIVATE Threads::Threads)
endif()
# For resource.h, purely so the CLI banner reads the same version constant the
# GUI and VERSIONINFO do rather than carrying a second copy to forget to bump.
target_include_directories(replay_cli PRIVATE "${CMAKE_SOURCE_DIR}/app")

# On Linux this is the whole product, so it gets the plain name as well.
if(NOT WIN32)
    set_target_properties(replay_cli PROPERTIES OUTPUT_NAME replay_cli)
    install(TARGETS replay_cli RUNTIME DESTINATION bin)
endif()
