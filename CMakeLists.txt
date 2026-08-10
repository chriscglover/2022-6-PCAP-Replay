cmake_minimum_required(VERSION 3.24)
project(PCAP_Replay
        VERSION 1.4.0
        DESCRIPTION "ST 2022-6/-7 replay from packet capture, with NMOS IS-04/IS-05"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

foreach(cfg "" _DEBUG _RELEASE _RELWITHDEBINFO _MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY${cfg} "${CMAKE_BINARY_DIR}/bin")
endforeach()

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /MP)
    add_compile_options($<$<CONFIG:Release>:/O2>)
    add_compile_definitions(
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
        # DnsServiceBrowse/Resolve/Register need Windows 10 1703 or later.
        _WIN32_WINNT=0x0A00)
    # Static CRT: deployment is "copy the exe". Unlike the NDI2022-6 rig there
    # is no runtime DLL to go with it -- nothing here links the NDI SDK.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_subdirectory(common)
add_subdirectory(nmos)
add_subdirectory(app)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/CMakeLists.txt")
    add_subdirectory(tools)
endif()

include(CTest)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()
