# pcapreplay_common -- SDI raster knowledge, the wire format, and the engines.
#
# Carried over from NDI2022-6's st2022_common with the NDI-facing half removed:
# no ndi_support, no sender_engine, no receiver_engine, and therefore no NDI SDK
# dependency at all. What is left is everything needed to read a capture and put
# ST 2022-6 back on the wire.

# AVX2 paths live in a dedicated TU so the rest of the library stays baseline
# x64 and the runtime probe in bitpack.cpp stays meaningful.
add_library(pcapreplay_avx2 STATIC src/bitpack_avx2.cpp)
target_include_directories(pcapreplay_avx2 PUBLIC include)
if(MSVC)
    target_compile_options(pcapreplay_avx2 PRIVATE /arch:AVX2)
endif()

add_library(pcapreplay_common STATIC
    src/sdi_format.cpp
    src/bitpack.cpp
    src/crc.cpp
    src/sdi_raster.cpp
    src/hbrmt.cpp
    src/net_interfaces.cpp
    src/net_multicast.cpp
    src/pacer.cpp
    src/pcap_source.cpp
    src/replay_engine.cpp
    src/stats_server.cpp
    src/settings.cpp
)

target_include_directories(pcapreplay_common PUBLIC include)
target_link_libraries(pcapreplay_common
    PUBLIC  pcapreplay_avx2
    PRIVATE ws2_32 iphlpapi winmm)
