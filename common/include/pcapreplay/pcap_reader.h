// Minimal classic-pcap reader and Ethernet/IPv4/UDP dissector.
//
// Streams the file, so capture size is not a constraint -- this app replays
// multi-gigabyte captures straight off disk rather than loading them.
//
// Carried over from the NDI2022-6 offline tools, with two changes for GUI use:
// errors are returned as a string rather than printed to a console that does
// not exist, and bytes read are counted so the GUI can show whether the disk is
// actually keeping up with line rate.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace pcapreplay {

struct PcapReader {
    std::FILE*    f = nullptr;
    bool          swap = false;
    bool          nanos = false;
    std::uint32_t linktype = 0;
    std::uint64_t bytesRead = 0;
    std::uint64_t fileBytes = 0;
    std::string   error;

    bool open(const std::string& path) {
        close();
        error.clear();
        bytesRead = 0;
        fopen_s(&f, path.c_str(), "rb");
        if (!f) { error = "cannot open " + path; return false; }

        // Big files are read strictly forwards; a large buffer keeps the read
        // syscall count down at the ~190 MB/s a 1080i25 leg demands.
        std::setvbuf(f, nullptr, _IOFBF, 1 << 20);

        _fseeki64(f, 0, SEEK_END);
        fileBytes = std::uint64_t(_ftelli64(f));
        _fseeki64(f, 0, SEEK_SET);

        std::uint8_t gh[24];
        if (std::fread(gh, 1, 24, f) != 24) {
            error = path + ": too short to be a pcap";
            return false;
        }
        std::uint32_t magic;
        std::memcpy(&magic, gh, 4);
        if      (magic == 0xa1b2c3d4) { swap = false; nanos = false; }
        else if (magic == 0xd4c3b2a1) { swap = true;  nanos = false; }
        else if (magic == 0xa1b23c4d) { swap = false; nanos = true; }
        else if (magic == 0x4d3cb2a1) { swap = true;  nanos = true; }
        else {
            char buf[128];
            std::snprintf(buf, sizeof buf,
                          ": unrecognised magic 0x%08X (pcapng is not supported; "
                          "re-save as classic pcap)", magic);
            error = path + buf;
            return false;
        }
        linktype = u32(gh + 20);
        bytesRead = 24;
        return true;
    }

    void rewindToFirstPacket() {
        if (f) { _fseeki64(f, 24, SEEK_SET); bytesRead = 24; }
    }

    std::uint32_t u32(const std::uint8_t* p) const {
        std::uint32_t v;
        std::memcpy(&v, p, 4);
        if (!swap) return v;
        return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
               ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
    }

    bool next(std::vector<std::uint8_t>& pkt) {
        std::uint8_t ph[16];
        if (std::fread(ph, 1, 16, f) != 16) return false;
        const std::uint32_t inclLen = u32(ph + 8);
        if (inclLen > 262144) return false;
        pkt.resize(inclLen);
        if (std::fread(pkt.data(), 1, inclLen, f) != inclLen) return false;
        bytesRead += 16 + inclLen;
        return true;
    }

    // Fraction of the file consumed, 0..1, for a progress readout.
    double progress() const {
        return fileBytes ? double(bytesRead) / double(fileBytes) : 0.0;
    }

    void close() { if (f) std::fclose(f); f = nullptr; }
    bool isOpen() const { return f != nullptr; }

    ~PcapReader() { close(); }
    PcapReader() = default;
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;
};

struct UdpView {
    std::uint32_t srcIp = 0, dstIp = 0;
    std::uint16_t srcPort = 0, dstPort = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t         len = 0;
};

inline std::string ipStr(std::uint32_t ip) {
    char b[24];
    std::snprintf(b, sizeof b, "%u.%u.%u.%u",
                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return b;
}

// Link-layer header size for the pcap linktypes we encounter.
//
// Captures taken with tcpdump on a Linux box are frequently LINKTYPE_RAW (101)
// -- the record starts at the IP header with no Ethernet framing at all. An
// Ethernet-only dissector silently rejects every packet in such a file.
// Returns -1 for "not a fixed offset" (Ethernet, handled separately).
inline int linkHeaderBytes(std::uint32_t linktype) {
    switch (linktype) {
        case 1:   return -1;   // Ethernet, may carry VLAN tags
        case 101: return 0;    // RAW: starts at the IP header
        case 12:  return 0;    // RAW_IP (BSD)
        case 228: return 0;    // IPV4
        case 113: return 16;   // LINUX_SLL
        case 276: return 20;   // LINUX_SLL2
        case 0:   return 4;    // NULL / loopback
        default:  return -2;   // unknown
    }
}

// Link layer -> IPv4 -> UDP. `linktype` comes from the pcap global header.
inline bool parseUdp(const std::uint8_t* p, std::size_t n, UdpView& out,
                     std::uint32_t linktype = 1) {
    std::size_t off = 0;

    const int fixed = linkHeaderBytes(linktype);
    if (fixed == -2) return false;
    if (fixed >= 0) {
        off = std::size_t(fixed);
        if (n < off + 20) return false;
        // Raw IP: sanity-check the version nibble rather than trusting an
        // ethertype we do not have.
        if ((p[off] >> 4) != 4) return false;
    } else {
        if (n < 14) return false;
        off = 12;
        std::uint16_t ethertype = std::uint16_t((p[off] << 8) | p[off + 1]);
        off += 2;
        while (ethertype == 0x8100 || ethertype == 0x88A8) {
            if (n < off + 4) return false;
            ethertype = std::uint16_t((p[off + 2] << 8) | p[off + 3]);
            off += 4;
        }
        if (ethertype != 0x0800) return false;
    }
    if (n < off + 20) return false;

    const std::uint8_t* ip = p + off;
    const std::size_t ihl = std::size_t(ip[0] & 0x0F) * 4;
    if (ihl < 20 || n < off + ihl + 8) return false;
    if (ip[9] != 17) return false;

    out.srcIp = (std::uint32_t(ip[12]) << 24) | (std::uint32_t(ip[13]) << 16) |
                (std::uint32_t(ip[14]) << 8)  |  std::uint32_t(ip[15]);
    out.dstIp = (std::uint32_t(ip[16]) << 24) | (std::uint32_t(ip[17]) << 16) |
                (std::uint32_t(ip[18]) << 8)  |  std::uint32_t(ip[19]);

    const std::uint8_t* udp = ip + ihl;
    out.srcPort = std::uint16_t((udp[0] << 8) | udp[1]);
    out.dstPort = std::uint16_t((udp[2] << 8) | udp[3]);
    const std::size_t udpLen = std::size_t((udp[4] << 8) | udp[5]);
    if (udpLen < 8) return false;

    out.payload = udp + 8;
    const std::size_t avail = n - (off + ihl + 8);
    out.len = udpLen - 8 < avail ? udpLen - 8 : avail;
    return true;
}

}  // namespace pcapreplay
