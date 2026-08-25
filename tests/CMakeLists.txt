# The test binary. One executable over every test file, registered at static
# initialisation, so adding a case means adding a file and nothing else.
#
# No framework is fetched: see tests/harness.h for why. That keeps the "no
# package manager anywhere" property the rest of the project depends on, and
# means `ctest` works on a machine with nothing installed but a compiler.
file(GLOB PCAPREPLAY_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(pcapreplay_tests ${PCAPREPLAY_TEST_SOURCES})
target_link_libraries(pcapreplay_tests PRIVATE pcapreplay_common pcapreplay_nmos)
target_include_directories(pcapreplay_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    # mdns_internal.h -- the record interpretation shared by both platforms'
    # browse engines is worth testing directly rather than only through a live
    # browse, which needs a network.
    "${CMAKE_SOURCE_DIR}/nmos/src")
if(NOT WIN32)
    target_link_libraries(pcapreplay_tests PRIVATE Threads::Threads)
endif()

# Registered as one test rather than one per case: the harness already reports
# which case failed and where, and a single invocation keeps the loopback
# servers the integration tests start from being spun up hundreds of times.
add_test(NAME pcapreplay_tests COMMAND pcapreplay_tests)

# The mDNS and loopback-HTTP cases wait on real sockets, so the default 1500 s
# is far more than needed but the point is that a hung socket fails the run
# rather than hanging the machine.
set_tests_properties(pcapreplay_tests PROPERTIES TIMEOUT 300)
