cmake_minimum_required(VERSION 3.24)
project(PCAP_Replay
        VERSION 1.6.0
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
    # Static CRT: deployment is "copy the exe" -- no runtime DLL to go with it,
    # and no external SDK is linked.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra)
    add_compile_options($<$<CONFIG:Release>:-O2>)
    if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
    endif()
    # Threads, and nothing else. There is no libpcap, no Avahi and no HTTP
    # library here -- see the README on why the NMOS and DNS-SD layers are
    # hand-rolled, which is the same reason on both platforms.
    find_package(Threads REQUIRED)
endif()

add_subdirectory(common)
add_subdirectory(nmos)
# The Win32 dialog. There is no Linux equivalent and there is not meant to be:
# on Linux the deliverable is replay_cli, which drives the same engines.
if(WIN32)
    add_subdirectory(app)
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/CMakeLists.txt")
    add_subdirectory(tools)
endif()

include(CTest)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

# Both platforms build the tests, and both need to: a Linux build compiles none
# of the Windows #ifdef branches and a Windows build compiles none of the Linux
# ones, so a suite run on one side alone leaves half the tree unexercised.
