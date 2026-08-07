// DNS-SD browse and advertise, on the Windows native API.
//
// Uses DnsServiceBrowse/DnsServiceResolve/DnsServiceRegister from dnsapi.dll
// (Windows 10 1703 and later) rather than Apple's Bonjour SDK. That keeps the
// app dependency-free and installable by copying it -- the Bonjour SDK is a
// gated download and its runtime is a separate install on every machine.
//
// Two directions, both of which NMOS needs:
//
//   browse    _nmos-register._tcp  -- find the registry to register with. This
//             is the normal path, and the reason the host/port override exists
//             is that plenty of real networks block mDNS across subnets.
//
//   advertise _nmos-node._tcp      -- peer-to-peer operation. With no registry
//             on the network at all, a controller that browses for nodes
//             directly can still find this sender and route it.
//
// Everything here is best-effort: on a network with no mDNS, or if the DNS
// client service refuses the registration, the caller carries on with whatever
// override it was given. Failures are reported, never fatal.
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace pcapreplay::nmos {

struct MdnsService {
    std::string instance;        // "registry._nmos-register._tcp.local"
    std::string displayName;     // the instance label alone
    std::string hostName;        // "server.local"
    std::string address;         // resolved IPv4, dotted quad
    std::uint16_t port = 0;
    std::map<std::string, std::string> txt;

    // Parsed out of the TXT record, per IS-04's DNS-SD binding.
    int         priority = 100;              // "pri"; lower wins
    std::string apiProto = "http";           // "api_proto"
    std::string apiAuth  = "false";          // "api_auth"
    std::vector<std::string> apiVersions;    // "api_ver", e.g. v1.2,v1.3

    bool supportsVersion(const std::string& v) const;
    std::string baseUrl(const std::string& apiVersion) const;
};

// Browses continuously and keeps a live list; NMOS registries come and go and a
// one-shot query would miss one that appears a second later.
class MdnsBrowser {
public:
    MdnsBrowser() = default;
    ~MdnsBrowser();
    MdnsBrowser(const MdnsBrowser&) = delete;
    MdnsBrowser& operator=(const MdnsBrowser&) = delete;

    // serviceType is the bare DNS-SD type, e.g. "_nmos-register._tcp".
    bool start(const std::string& serviceType);
    void stop();
    bool running() const { return running_; }

    std::vector<MdnsService> found() const;

    // Highest-priority resolved service supporting `apiVersion`, if any.
    bool best(const std::string& apiVersion, MdnsService& out) const;

    std::string error() const;

private:
    struct Impl;
    void onInstance(MdnsService s);
    void onError(const std::string& e);

    mutable std::mutex       mutex_;
    std::vector<MdnsService> found_;
    std::string              error_;
    bool                     running_ = false;
    Impl*                    impl_ = nullptr;
};

// Advertises one service instance for as long as it is alive.
class MdnsAdvertiser {
public:
    MdnsAdvertiser() = default;
    ~MdnsAdvertiser();
    MdnsAdvertiser(const MdnsAdvertiser&) = delete;
    MdnsAdvertiser& operator=(const MdnsAdvertiser&) = delete;

    // `instanceLabel` is the human-readable name, e.g. "PCAP Replay".
    // `hostIpv4` is the address to publish; empty uses the local hostname.
    bool start(const std::string& instanceLabel,
               const std::string& serviceType,
               std::uint16_t port,
               const std::map<std::string, std::string>& txt,
               const std::string& hostIpv4 = {});
    void stop();

    bool running() const { return running_; }
    std::string error() const;

private:
    struct Impl;
    Impl*       impl_ = nullptr;
    bool        running_ = false;
    mutable std::mutex mutex_;
    std::string error_;
};

// Local host label without the domain, e.g. "EDIT-1". Used to build unique
// instance names and the node's hostname.
std::string localHostLabel();

}  // namespace pcapreplay::nmos
