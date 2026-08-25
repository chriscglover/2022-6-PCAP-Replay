#include "harness.h"

#include "pcapreplay/platform.h"

int main(int argc, char** argv) {
    // Winsock has to be started before any socket call, and the test binary is
    // an application like any other -- replay_cli and the dialog both do this
    // at the top of main(). Without it every socket() on Windows fails with
    // WSANOTINITIALISED and the HTTP, NMOS and mDNS suites skip themselves for
    // what looks like a locked-down runner. A no-op on POSIX, which is exactly
    // why its absence was invisible until CI built the other platform.
    const pcapreplay::SocketScope sockets;

    return ::test::runAll(argc, argv);
}
