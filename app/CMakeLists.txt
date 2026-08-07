add_executable(pcap_replay WIN32
    main.cpp
    app.rc
)

target_link_libraries(pcap_replay PRIVATE
    pcapreplay_common
    pcapreplay_nmos
    comctl32)

target_include_directories(pcap_replay PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(pcap_replay PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\"")
