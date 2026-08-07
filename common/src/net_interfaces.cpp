#include "pcapreplay/net_interfaces.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <memory>

namespace pcapreplay {
namespace {

std::string wideToUtf8(const wchar_t* w) {
    if (!w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(std::size_t(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

bool looksVirtual(const std::string& name, const std::string& desc, IFTYPE ifType) {
    if (ifType == IF_TYPE_SOFTWARE_LOOPBACK || ifType == IF_TYPE_TUNNEL) return true;
    static const char* const markers[] = {
        "hyper-v", "vethernet", "virtual", "vmware", "virtualbox",
        "tap-", "tun", "loopback", "wan miniport", "bluetooth",
    };
    std::string hay = name + " " + desc;
    std::transform(hay.begin(), hay.end(), hay.begin(),
                   [](unsigned char c) { return char(std::tolower(c)); });
    for (const char* m : markers)
        if (hay.find(m) != std::string::npos) return true;
    return false;
}

std::string speedText(std::uint64_t bps) {
    char b[32];
    if (bps >= 1000000000ull) std::snprintf(b, sizeof b, "%.0f Gb/s", double(bps) / 1e9);
    else if (bps >= 1000000ull) std::snprintf(b, sizeof b, "%.0f Mb/s", double(bps) / 1e6);
    else return {};
    return b;
}

}  // namespace

std::string NetInterface::displayName() const {
    // Loopback does NOT avoid the local-subscriber penalty -- measured at
    // ~125 us/datagram either way. It is offered for connectivity testing only.
    if (loopback) return "Loopback " + ipv4 + " - low rate only, see docs";
    std::string s = name.empty() ? description : name;
    if (!ipv4.empty()) s += " - " + ipv4;
    const std::string sp = speedText(speedBps);
    if (!sp.empty()) s += " (" + sp + ")";
    if (!up) s += " [down]";
    return s;
}

std::vector<NetInterface> enumerateInterfaces(bool includeDown) {
    std::vector<NetInterface> out;

    ULONG size = 16 * 1024;
    std::unique_ptr<std::uint8_t[]> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf = std::make_unique<std::uint8_t[]>(size);
        rc = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get()),
            &size);
    }
    if (rc != NO_ERROR) return out;

    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get()); a; a = a->Next) {
        const bool up = a->OperStatus == IfOperStatusUp;
        const bool loopback = a->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        const bool mcast = (a->Flags & IP_ADAPTER_NO_MULTICAST) == 0;
        // Loopback is kept: it is the only way to run the sender and receiver
        // on one machine at line rate. Sending to a group that this host has
        // joined costs ~125 us per datagram through a physical NIC (8k/s) but
        // runs at 328k/s through loopback. It sorts last so it is never the
        // default.
        if (!includeDown && (!up || !mcast)) continue;

        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            const auto* sin = reinterpret_cast<const sockaddr_in*>(ua->Address.lpSockaddr);

            NetInterface ni;
            ni.name        = wideToUtf8(a->FriendlyName);
            ni.description = wideToUtf8(a->Description);
            ni.index       = a->IfIndex;
            ni.speedBps    = a->TransmitLinkSpeed == static_cast<ULONG64>(-1)
                                 ? 0 : a->TransmitLinkSpeed;
            ni.up          = up;
            ni.loopback    = loopback;
            ni.multicastCapable = mcast;
            ni.virtualAdapter = looksVirtual(ni.name, ni.description, a->IfType);
            ni.ipv4Be      = sin->sin_addr.S_un.S_addr;

            // Hyphenated lower case, which is the form NMOS uses for a node's
            // interface chassis_id/port_id and RFC 7273 for ts-refclk:localmac.
            if (a->PhysicalAddressLength == 6) {
                char mac[18];
                std::snprintf(mac, sizeof mac, "%02x-%02x-%02x-%02x-%02x-%02x",
                              a->PhysicalAddress[0], a->PhysicalAddress[1],
                              a->PhysicalAddress[2], a->PhysicalAddress[3],
                              a->PhysicalAddress[4], a->PhysicalAddress[5]);
                ni.mac = mac;
            }

            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
            ni.ipv4 = ip;

            out.push_back(std::move(ni));
        }
    }

    // Up first, then physical before virtual, then fastest. A Hyper-V vSwitch
    // reports the same 10 Gb/s as the NIC it sits on, so speed alone would let
    // it become the default -- and multicast out of the wrong interface fails
    // silently.
    std::stable_sort(out.begin(), out.end(), [](const NetInterface& a, const NetInterface& b) {
        if (a.up != b.up) return a.up;
        if (a.loopback != b.loopback) return !a.loopback;
        if (a.virtualAdapter != b.virtualAdapter) return !a.virtualAdapter;
        return a.speedBps > b.speedBps;
    });

    // Guarantee a loopback entry even if the pseudo-interface is not enumerated,
    // so same-machine testing is always selectable.
    const bool haveLoopback = std::any_of(out.begin(), out.end(),
        [](const NetInterface& n) { return n.loopback; });
    if (!haveLoopback) {
        NetInterface lo;
        lo.name = "Loopback";
        lo.description = "Loopback Pseudo-Interface";
        lo.ipv4 = "127.0.0.1";
        lo.ipv4Be = htonl(INADDR_LOOPBACK);
        lo.up = true;
        lo.loopback = true;
        lo.multicastCapable = true;
        out.push_back(std::move(lo));
    }
    return out;
}

bool findInterfaceByIp(const std::string& ipv4, NetInterface& out) {
    for (const auto& ni : enumerateInterfaces(true))
        if (ni.ipv4 == ipv4) { out = ni; return true; }
    return false;
}

bool parseIpv4(const std::string& s, std::uint32_t& beOut) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
    beOut = a.S_un.S_addr;
    return true;
}

bool isValidMulticastGroup(const std::string& ipv4) {
    std::uint32_t be = 0;
    if (!parseIpv4(ipv4, be)) return false;
    const std::uint32_t host = ntohl(be);
    // 224.0.0.0/4, excluding the link-local control block 224.0.0.0/24 which
    // routers never forward.
    if ((host & 0xF0000000u) != 0xE0000000u) return false;
    if ((host & 0xFFFFFF00u) == 0xE0000000u) return false;
    return true;
}

}  // namespace pcapreplay
