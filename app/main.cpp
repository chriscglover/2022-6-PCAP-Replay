// PCAP Replay -- an ST 2022-6/-7 source that plays back packet captures.
//
// Built on an earlier ST 2022-6 replay engine, with two changes:
//
//   1. The source is a pcap capture rather than an extracted .sdi raster, and
//      two captures are merged as an ST 2022-7 pair, so a datagram lost on one
//      leg is filled from the other. Captures stream off disk through a small
//      ring buffer, so a multi-gigabyte file plays in full rather than the
//      first few seconds of it fitting in RAM.
//   2. It is an NMOS sender: it registers with a registry over IS-04, serves
//      IS-05 so a controller can route and activate it, and publishes an SDP.
//
// Everything else is as it was: indefinite looping with fresh RTP and HBRMT
// headers so the loop join is invisible, live timecode rewriting, and random
// impairments for exercising a receiver.
//
// Same split as before: the GUI owns configuration and display, the engine owns
// everything real. Native Win32 dialog, no toolkit.

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "pcapreplay/net_interfaces.h"
#include "pcapreplay/replay_engine.h"
#include "pcapreplay/settings.h"
#include "pcapreplay/stats_server.h"
#include "pcapreplay/nmos/http.h"
#include "pcapreplay/nmos/nmos_node.h"
#include "resource.h"

using namespace pcapreplay;

namespace {

constexpr UINT_PTR kTimerStatus = 1;

// ---- instance slot ---------------------------------------------------------
//
// Everything that has to differ between two copies on one machine -- the node
// API port, the stats port and the settings file -- comes from a single slot
// number, so the three cannot drift apart. Slot 0 is the first instance and
// keeps the file and the ports it has always had, so nothing about an existing
// single-instance install changes.
//
// There is a chicken and egg in keying settings by the node port: the configured
// port lives in settings. It is broken by reading the *base* port from the
// shared store -- the port every instance starts probing from, which is by
// definition the same value for all of them -- and only then opening the real
// store, keyed on where this instance actually landed.
//
// A slot is claimed only when both its ports are free. Keying on the node port
// alone would drop two instances into the same settings file whenever the first
// had NMOS switched off and so never bound one.
constexpr std::uint16_t kDefaultNodePort = 3210;

struct InstanceSlot {
    int           index = 0;
    std::uint16_t nodePort  = kDefaultNodePort;
    std::uint16_t statsPort = kReplayStatsPort;
    std::string   settingsName = "replay";
};

InstanceSlot resolveInstanceSlot() {
    // The shared store, read for one value only: where to start probing.
    const Settings shared{"replay"};
    const int configured = shared.getInt("nmos_port", kDefaultNodePort);
    const std::uint16_t base =
        (configured > 0 && configured < 65536) ? std::uint16_t(configured)
                                               : kDefaultNodePort;

    InstanceSlot slot;
    for (int i = 0; i < 20; ++i) {
        const int node  = int(base) + i;
        const int stats = int(kReplayStatsPort) + i;
        if (node > 65535 || stats > 65535) break;
        // span 1 asks "is this exact port free", not "find me one near it".
        if (nmos::firstFreePort({}, std::uint16_t(node), 1) == 0) continue;
        if (nmos::firstFreePort("127.0.0.1", std::uint16_t(stats), 1) == 0) continue;

        slot.index     = i;
        slot.nodePort  = std::uint16_t(node);
        slot.statsPort = std::uint16_t(stats);
        slot.settingsName = i == 0 ? "replay" : ("replay-" + std::to_string(node));
        return slot;
    }
    // Every slot taken. Fall back to the first and let the individual servers
    // report their own bind failures rather than inventing one here.
    slot.nodePort  = base;
    slot.statsPort = kReplayStatsPort;
    return slot;
}

// The settings a given instance sees.
//
// Writes always go to this instance's own file, which is the whole point: two
// copies must not overwrite each other's remembered paths and ports.
//
// Reads fall through to the first instance's file when this one has no answer,
// which matters as much. A second instance opening completely blank -- no
// capture, no NIC, NMOS switched off -- is not a useful second instance; you
// almost always want another copy of roughly the same thing. Inheriting the
// defaults and then diverging on whatever you change is the behaviour that makes
// a second instance worth starting.
class InstanceSettings {
public:
    InstanceSettings(const std::string& name, bool inherit) : own_(name) {
        if (inherit) base_.emplace("replay");
    }

    std::string getString(const char* k, const std::string& fb) const {
        return base_ ? own_.getString(k, base_->getString(k, fb))
                     : own_.getString(k, fb);
    }
    int getInt(const char* k, int fb) const {
        return base_ ? own_.getInt(k, base_->getInt(k, fb)) : own_.getInt(k, fb);
    }
    bool getBool(const char* k, bool fb) const { return getInt(k, fb ? 1 : 0) != 0; }

    // For the few values that must not be inherited because they are what makes
    // this instance distinct -- inheriting the node port would have every copy
    // trying to bind the first one's.
    int getIntOwn(const char* k, int fb) const { return own_.getInt(k, fb); }

    void setString(const char* k, const std::string& v) { own_.setString(k, v); }
    void setInt(const char* k, int v)                   { own_.setInt(k, v); }
    void setBool(const char* k, bool v)                 { own_.setBool(k, v); }

    const std::string& path() const { return own_.path(); }

private:
    Settings                own_;
    std::optional<Settings> base_;   // engaged only for instances after the first
};

struct App {
    WinsockScope  winsock;
    ReplayEngine  engine;
    StatsServer   stats;
    // Opened once the instance slot is known, so two copies on one machine do
    // not overwrite each other's remembered paths and ports. See InstanceSlot.
    std::optional<InstanceSettings> settings;
    InstanceSlot  slot;
    std::vector<NetInterface> interfaces;

    std::unique_ptr<nmos::NmosBackend> nmos{nmos::createBuiltinBackend()};

    // Guards `cfg` and the engine start/stop pair, which the GUI thread and an
    // IS-05 activation on an HTTP worker thread both reach for.
    std::mutex    controlMutex;
    ReplayConfig  cfg;
    int           frameRateNum = 25, frameRateDen = 1;
    // Format of the selected capture, learnt at probe time. The engine only
    // reports one while it is running, and the NMOS label wants to say what is
    // loaded from the moment it is picked, not from the moment it is playing.
    std::string   probedFormat;
    // Read by the stats server thread, which must not reach into the dialog for
    // it -- a cross-thread SendMessage to a UI thread busy inside an IS-05
    // activation would deadlock the pair.
    std::atomic<bool> nmosEnabled{false};
    bool          uiDirty = false;
    // Set when IS-05 changed the transport behind the GUI's back, so the dialog
    // fields can be brought back into line with it. Without this the next thing
    // that reads the fields -- a fault checkbox, or the Start button -- would
    // quietly put the old multicast group back.
    bool          fieldsDirty = false;
};

// ---- small helpers ---------------------------------------------------------

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), nullptr, 0);
    std::wstring w(std::size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string s(std::size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string getText(HWND dlg, int id) {
    wchar_t buf[1024] = {};
    GetDlgItemTextW(dlg, id, buf, 1024);
    return narrow(buf);
}
void setText(HWND dlg, int id, const std::string& s) {
    // Only touch the control if the text actually changed: rewriting a static
    // every 250 ms makes it flicker, and rewriting an edit box steals the
    // caret from anyone typing in it.
    wchar_t cur[4096] = {};
    GetDlgItemTextW(dlg, id, cur, 4096);
    const std::wstring want = widen(s);
    if (want != cur) SetDlgItemTextW(dlg, id, want.c_str());
}
bool checked(HWND dlg, int id) { return IsDlgButtonChecked(dlg, id) == BST_CHECKED; }
void check(HWND dlg, int id, bool on) {
    CheckDlgButton(dlg, id, on ? BST_CHECKED : BST_UNCHECKED);
}
void enable(HWND dlg, int id, bool on) { EnableWindow(GetDlgItem(dlg, id), on); }

std::string commas(std::uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(std::size_t(i), ",");
    return s;
}

std::string bytesText(std::uint64_t b) {
    char buf[48];
    if (b >= (1ull << 30)) std::snprintf(buf, sizeof buf, "%.2f GB", double(b) / (1ull << 30));
    else                   std::snprintf(buf, sizeof buf, "%.1f MB", double(b) / (1ull << 20));
    return buf;
}

void fillInterfaces(HWND dlg, App& app) {
    app.interfaces = enumerateInterfaces();
    for (int id : {IDC_A_IFACE, IDC_B_IFACE, IDC_NMOS_IFACE}) {
        HWND c = GetDlgItem(dlg, id);
        SendMessageW(c, CB_RESETCONTENT, 0, 0);
        for (const auto& ni : app.interfaces)
            SendMessageW(c, CB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(widen(ni.displayName()).c_str()));
        // enumerateInterfaces() puts physical NICs first, so 0 is a sane default
        // rather than a Hyper-V vSwitch.
        SendMessageW(c, CB_SETCURSEL, 0, 0);
    }
}

void selectIface(HWND dlg, App& app, int id, const std::string& ip) {
    if (ip.empty()) return;
    for (std::size_t i = 0; i < app.interfaces.size(); ++i)
        if (app.interfaces[i].ipv4 == ip) {
            SendMessageW(GetDlgItem(dlg, id), CB_SETCURSEL, int(i), 0);
            return;
        }
}

std::string ifaceIp(HWND dlg, App& app, int id) {
    const int sel = int(SendMessageW(GetDlgItem(dlg, id), CB_GETCURSEL, 0, 0));
    if (sel < 0 || sel >= int(app.interfaces.size())) return {};
    return app.interfaces[std::size_t(sel)].ipv4;
}

std::string ifaceNameFor(App& app, const std::string& ip) {
    for (const auto& ni : app.interfaces)
        if (ni.ipv4 == ip) return ni.name;
    return ip.empty() ? std::string("eth0") : ip;
}

std::string ifaceMacFor(App& app, const std::string& ip) {
    for (const auto& ni : app.interfaces)
        if (ni.ipv4 == ip) return ni.mac;
    return {};
}

// ---- NMOS bridge -----------------------------------------------------------

nmos::SenderTransport queryTransport(App& app) {
    std::lock_guard<std::mutex> lk(app.controlMutex);
    nmos::SenderTransport t;

    // While the engine is running, report what it is actually transmitting, not
    // what the GUI last asked for. The two are different objects and they do
    // come apart -- an IS-05 activation that fails to restart the engine, or a
    // GUI field edited but not applied, would otherwise have the Node API, the
    // IS-05 active endpoint and the SDP all confidently advertising a multicast
    // group nothing is being sent to. A controller believes the manifest, so a
    // wrong one is worse than a stale one.
    const bool live = app.engine.running();
    const ReplayConfig liveCfg = app.engine.activeConfig();
    const ReplayConfig& c = live ? liveCfg : app.cfg;
    t.active      = live;
    t.redundant   = c.enablePathB;
    t.sourceIpA   = c.pathA.interfaceIp;
    t.sourceIpB   = c.pathB.interfaceIp;
    t.destIpA     = c.pathA.group;
    t.destPortA   = c.pathA.port;
    t.destIpB     = c.pathB.group;
    t.destPortB   = c.pathB.port;
    t.ttl         = c.ttl;
    t.ssrc        = c.ssrc;
    t.payloadType = 98;
    t.interfaceNameA = ifaceNameFor(app, c.pathA.interfaceIp);
    t.interfaceNameB = ifaceNameFor(app, c.pathB.interfaceIp);
    t.macA           = ifaceMacFor(app, c.pathA.interfaceIp);
    t.macB           = ifaceMacFor(app, c.pathB.interfaceIp);
    t.frameRateNum = app.frameRateNum;
    t.frameRateDen = app.frameRateDen;
    t.formatText   = live ? app.engine.status().formatText : app.probedFormat;
    return t;
}

// Called from an IS-05 activation, on an HTTP worker thread.
//
// Changing the destination means restarting the engine: the transmit sockets are
// bound to their group at open, so there is nothing to retune in place. That
// restart has to be confirmed rather than assumed. A controller takes a 200 here
// as "the sender has moved", and if the engine failed to come back up on the new
// group -- a NIC that has gone away, a group the stack will not take -- then
// answering 200 tells the controller a lie it will not find out about.
bool applyTransport(App& app, const nmos::SenderTransport& want, std::string& err) {
    ReplayConfig previous;
    bool started = false;
    {
        std::lock_guard<std::mutex> lk(app.controlMutex);
        previous = app.cfg;

        ReplayConfig cfg = app.cfg;
        cfg.pathA.group = want.destIpA;
        cfg.pathA.port  = want.destPortA;
        if (cfg.enablePathB) {
            cfg.pathB.group = want.destIpB;
            cfg.pathB.port  = want.destPortB;
        }

        if (want.active) {
            if (cfg.fileRed.empty() && cfg.fileBlue.empty()) {
                err = "no capture file has been selected in the application";
                return false;
            }
            if (!isValidMulticastGroup(cfg.pathA.group)) {
                err = "destination_ip " + cfg.pathA.group +
                      " is not a usable multicast group";
                return false;
            }
            if (cfg.enablePathB && !isValidMulticastGroup(cfg.pathB.group)) {
                err = "second leg destination_ip " + cfg.pathB.group +
                      " is not a usable multicast group";
                return false;
            }
            if (cfg.enablePathB && cfg.pathA.group == cfg.pathB.group &&
                cfg.pathA.port == cfg.pathB.port) {
                err = "both ST 2022-7 legs would point at " + cfg.pathA.group +
                      ":" + std::to_string(cfg.pathA.port) +
                      ", which is not redundancy";
                return false;
            }
            app.cfg = cfg;
            app.engine.start(cfg);
            started = true;
        } else {
            app.cfg = cfg;
            app.engine.stop();
        }
        app.uiDirty = true;
        app.fieldsDirty = true;
    }

    if (!started) return true;

    // Wait for the restart to settle, outside the lock so the GUI keeps
    // repainting. status().running goes true only once both transmit sockets are
    // open, and running() goes false if the engine gave up, so one of the two
    // answers arrives -- typically within a frame or two, but opening the first
    // frame out of a large capture can take longer.
    using namespace std::chrono;
    const auto deadline = steady_clock::now() + seconds(10);
    for (;;) {
        const ReplayStatus s = app.engine.status();
        if (s.running) break;
        if (!app.engine.running()) {
            err = s.error.empty() ? "the replay engine did not start" : s.error;
            std::lock_guard<std::mutex> lk(app.controlMutex);
            app.cfg = previous;          // do not advertise a group we never used
            app.uiDirty = true;
            app.fieldsDirty = true;
            return false;
        }
        if (steady_clock::now() >= deadline) {
            err = "the replay engine did not come up within 10 s";
            return false;
        }
        std::this_thread::sleep_for(milliseconds(20));
    }
    return true;
}

// ---- source description ----------------------------------------------------

void describeFiles(HWND dlg, App& app) {
    const std::string red  = getText(dlg, IDC_RED);
    const std::string blue = getText(dlg, IDC_BLUE);
    if (red.empty() && blue.empty()) {
        setText(dlg, IDC_FILEINFO, "");
        return;
    }
    const PcapProbe p = ReplayEngine::probe(red, blue);
    if (!p.ok) {
        setText(dlg, IDC_FILEINFO, "!! " + p.error);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(app.controlMutex);
        const SdiFormatInfo& fi = formatInfo(p.format);
        app.frameRateNum = fi.frameRateNum;
        app.frameRateDen = fi.frameRateDen;
        app.probedFormat = p.formatText;
    }
    // The NMOS labels carry the format, so a new capture is a resource change a
    // registry should hear about rather than discover at the next restart.
    app.nmos->notifyChanged();

    const SdiFormatInfo& fi = formatInfo(p.format);
    const int ring = GetDlgItemInt(dlg, IDC_RING, nullptr, FALSE);
    const double ringMb = double(fi.bytesPerFrame()) * (ring > 0 ? ring : 16) / 1048576.0;

    const std::string blueText =
        p.blueAddress.empty() ? std::string() : "  blue " + p.blueAddress;

    char buf[512];
    std::snprintf(buf, sizeof buf,
        "%s   %s   red %s%s\r\n"
        "about %.0f s of capture   -   ring buffer %.0f MB   -   disk needs %.0f MB/s",
        p.formatText.c_str(),
        p.blueAddress.empty() ? "single path" : "ST 2022-7 pair",
        p.redAddress.c_str(),
        blueText.c_str(),
        p.estimatedSeconds, ringMb,
        fi.bitsPerSecond() / 8.0 / 1e6 * (p.blueAddress.empty() ? 1.0 : 2.0) * 1.04);

    std::string info = buf;
    if (!p.warning.empty()) info += "\r\n!! " + p.warning;
    setText(dlg, IDC_FILEINFO, info);
}

// ---- UI state --------------------------------------------------------------

void updateModeUi(HWND dlg, bool running) {
    const bool seven = checked(dlg, IDC_MODE_7);
    for (int id : {IDC_B_GROUP, IDC_B_PORT, IDC_B_IFACE})
        enable(dlg, id, seven && !running);
    enable(dlg, IDC_F_LOSS_B, seven);
}

void updateNmosUi(HWND dlg) {
    const bool on = checked(dlg, IDC_NMOS_EN);
    const bool manual = checked(dlg, IDC_NMOS_MANUAL);
    for (int id : {IDC_NMOS_LABEL, IDC_NMOS_PORT, IDC_NMOS_IFACE,
                   IDC_NMOS_MDNS, IDC_NMOS_MANUAL, IDC_NMOS_P2P})
        enable(dlg, id, on);
    enable(dlg, IDC_NMOS_HOST,  on && manual);
    enable(dlg, IDC_NMOS_RPORT, on && manual);
}

void setRunningUi(HWND dlg, bool running) {
    setText(dlg, IDC_START, running ? "Stop" : "Start");
    for (int id : {IDC_RED, IDC_RED_BROWSE, IDC_BLUE, IDC_BLUE_BROWSE,
                   IDC_RING, IDC_SKIP,
                   IDC_MODE_6, IDC_MODE_7,
                   IDC_A_GROUP, IDC_A_PORT, IDC_A_IFACE,
                   IDC_B_GROUP, IDC_B_PORT, IDC_B_IFACE,
                   IDC_TTL, IDC_LOOPBACK, IDC_TIMECODE, IDC_DURATION})
        enable(dlg, id, !running);
    if (!running) updateModeUi(dlg, false);
    else          updateModeUi(dlg, true);
    // Faults stay live while running -- flipping impairments mid-stream is the
    // whole point of having them on tick boxes.
}

// Put the transmit fields back in step with the configuration actually in force.
//
// IS-05 can move the sender without the GUI knowing, and every path that starts
// the engine builds its config from these fields -- so leaving them stale means
// the next fault checkbox or Start press silently reinstates the old multicast
// group and undoes the controller's routing. Called on the GUI thread only.
void setTransmitFields(HWND dlg, const ReplayConfig& cfg) {
    setText(dlg, IDC_A_GROUP, cfg.pathA.group);
    SetDlgItemInt(dlg, IDC_A_PORT, UINT(cfg.pathA.port), FALSE);
    setText(dlg, IDC_B_GROUP, cfg.pathB.group);
    SetDlgItemInt(dlg, IDC_B_PORT, UINT(cfg.pathB.port), FALSE);
}

void doBrowse(HWND dlg, App& app, int editId) {
    wchar_t path[MAX_PATH] = {};
    const std::string cur = getText(dlg, editId);
    if (!cur.empty()) wcsncpy_s(path, widen(cur).c_str(), _TRUNCATE);

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner   = dlg;
    ofn.lpstrFilter = L"Packet capture (*.pcap)\0*.pcap\0All files\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = editId == IDC_RED ? L"Red (path A) capture"
                                        : L"Blue (path B) capture";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    setText(dlg, editId, narrow(path));
    describeFiles(dlg, app);
}

ReplayFaults faultsFrom(HWND dlg) {
    ReplayFaults f;
    f.lossA     = checked(dlg, IDC_F_LOSS_A);
    f.lossB     = checked(dlg, IDC_F_LOSS_B);
    f.burstLoss = checked(dlg, IDC_F_BURST);
    f.reorder   = checked(dlg, IDC_F_REORDER);
    f.duplicate = checked(dlg, IDC_F_DUP);
    f.seqJump   = checked(dlg, IDC_F_SEQJUMP);
    f.ratePercent = std::atof(getText(dlg, IDC_F_RATE).c_str());
    if (f.ratePercent <= 0.0) f.ratePercent = 0.1;
    return f;
}

ReplayConfig configFrom(HWND dlg, App& app) {
    ReplayConfig cfg;
    cfg.fileRed  = getText(dlg, IDC_RED);
    cfg.fileBlue = getText(dlg, IDC_BLUE);
    cfg.ringFrames    = int(GetDlgItemInt(dlg, IDC_RING, nullptr, FALSE));
    cfg.skipTolerance = int(GetDlgItemInt(dlg, IDC_SKIP, nullptr, FALSE));
    if (cfg.ringFrames < 2)      cfg.ringFrames = 16;
    if (cfg.skipTolerance < 1)   cfg.skipTolerance = 10;

    cfg.enablePathB = checked(dlg, IDC_MODE_7);
    cfg.pathA.group = getText(dlg, IDC_A_GROUP);
    cfg.pathA.port  = std::uint16_t(GetDlgItemInt(dlg, IDC_A_PORT, nullptr, FALSE));
    cfg.pathA.interfaceIp = ifaceIp(dlg, app, IDC_A_IFACE);
    cfg.pathB.group = getText(dlg, IDC_B_GROUP);
    cfg.pathB.port  = std::uint16_t(GetDlgItemInt(dlg, IDC_B_PORT, nullptr, FALSE));
    cfg.pathB.interfaceIp = ifaceIp(dlg, app, IDC_B_IFACE);
    cfg.ttl = int(GetDlgItemInt(dlg, IDC_TTL, nullptr, FALSE));
    cfg.loopback = checked(dlg, IDC_LOOPBACK);
    cfg.rewriteTimecode = checked(dlg, IDC_TIMECODE);
    cfg.maxSeconds = double(GetDlgItemInt(dlg, IDC_DURATION, nullptr, FALSE));
    cfg.faults = faultsFrom(dlg);
    return cfg;
}

nmos::NmosConfig nmosConfigFrom(HWND dlg, App& app) {
    nmos::NmosConfig n;
    n.enabled  = checked(dlg, IDC_NMOS_EN);
    n.label    = getText(dlg, IDC_NMOS_LABEL);
    if (n.label.empty()) n.label = "PCAP Replay";
    n.nodePort = std::uint16_t(GetDlgItemInt(dlg, IDC_NMOS_PORT, nullptr, FALSE));
    n.nodeIp   = ifaceIp(dlg, app, IDC_NMOS_IFACE);
    n.useMdns  = checked(dlg, IDC_NMOS_MDNS);
    if (checked(dlg, IDC_NMOS_MANUAL)) {
        n.registryHost = getText(dlg, IDC_NMOS_HOST);
        n.registryPort = std::uint16_t(GetDlgItemInt(dlg, IDC_NMOS_RPORT, nullptr, FALSE));
        if (n.registryPort == 0) n.registryPort = 3210;
    }
    n.advertisePeerToPeer = checked(dlg, IDC_NMOS_P2P);
    return n;
}

void saveSettings(HWND dlg, App& app, const ReplayConfig& cfg) {
    if (!app.settings) return;
    auto& st = *app.settings;
    st.setString("red",      cfg.fileRed);
    st.setString("blue",     cfg.fileBlue);
    st.setInt   ("ring",     cfg.ringFrames);
    st.setInt   ("skip",     cfg.skipTolerance);
    st.setBool  ("seven",    cfg.enablePathB);
    st.setString("a_group",  cfg.pathA.group);
    st.setInt   ("a_port",   cfg.pathA.port);
    st.setString("a_iface",  cfg.pathA.interfaceIp);
    st.setString("b_group",  cfg.pathB.group);
    st.setInt   ("b_port",   cfg.pathB.port);
    st.setString("b_iface",  cfg.pathB.interfaceIp);
    st.setInt   ("ttl",      cfg.ttl);
    st.setBool  ("loopback", cfg.loopback);
    st.setBool  ("timecode", cfg.rewriteTimecode);
    st.setInt   ("duration", int(cfg.maxSeconds));

    st.setBool  ("nmos",       checked(dlg, IDC_NMOS_EN));
    st.setString("nmos_label", getText(dlg, IDC_NMOS_LABEL));
    st.setInt   ("nmos_port",  int(GetDlgItemInt(dlg, IDC_NMOS_PORT, nullptr, FALSE)));
    st.setString("nmos_iface", ifaceIp(dlg, app, IDC_NMOS_IFACE));
    st.setBool  ("nmos_mdns",  checked(dlg, IDC_NMOS_MDNS));
    st.setString("nmos_host",  getText(dlg, IDC_NMOS_HOST));
    st.setInt   ("nmos_rport", int(GetDlgItemInt(dlg, IDC_NMOS_RPORT, nullptr, FALSE)));
    st.setBool  ("nmos_p2p",   checked(dlg, IDC_NMOS_P2P));
}

void startNmos(HWND dlg, App& app) {
    const nmos::NmosConfig n = nmosConfigFrom(dlg, app);
    app.nmosEnabled.store(n.enabled, std::memory_order_relaxed);
    if (!n.enabled) {
        app.nmos->stop();
        return;
    }
    app.nmos->setCallbacks([&app] { return queryTransport(app); },
                           [&app](const nmos::SenderTransport& want, std::string& err) {
                               return applyTransport(app, want, err);
                           });
    app.nmos->start(n);
}

void doStart(HWND dlg, App& app) {
    const ReplayConfig cfg = configFrom(dlg, app);

    if (cfg.fileRed.empty() && cfg.fileBlue.empty()) {
        MessageBoxW(dlg, L"Pick a red and/or blue capture first.\n\n"
                         L"Give it both legs of an ST 2022-7 pair and they are "
                         L"merged, so a datagram lost on one leg is filled from "
                         L"the other.",
                    L"PCAP Replay", MB_ICONWARNING);
        return;
    }
    if (!isValidMulticastGroup(cfg.pathA.group)) {
        MessageBoxW(dlg, L"Path A group is not a usable multicast address.\n\n"
                         L"Use 224.0.1.0 - 239.255.255.255; 224.0.0.0/24 is the "
                         L"link-local control block and is never forwarded.",
                    L"PCAP Replay", MB_ICONWARNING);
        return;
    }
    if (cfg.enablePathB) {
        if (!isValidMulticastGroup(cfg.pathB.group)) {
            MessageBoxW(dlg, L"Path B group is not a usable multicast address.",
                        L"PCAP Replay", MB_ICONWARNING);
            return;
        }
        if (cfg.pathA.group == cfg.pathB.group && cfg.pathA.port == cfg.pathB.port) {
            MessageBoxW(dlg, L"Both ST 2022-7 paths point at the same group and "
                             L"port, so there is no redundancy at all.",
                        L"PCAP Replay", MB_ICONWARNING);
            return;
        }
    }

    saveSettings(dlg, app, cfg);
    {
        std::lock_guard<std::mutex> lk(app.controlMutex);
        app.cfg = cfg;
        app.engine.start(cfg);
    }
    setRunningUi(dlg, true);
    app.nmos->notifyChanged();
}

void doStop(HWND dlg, App& app) {
    {
        std::lock_guard<std::mutex> lk(app.controlMutex);
        app.engine.stop();
    }
    setRunningUi(dlg, false);
    app.nmos->notifyChanged();
}

// ---- status text -----------------------------------------------------------

// Prefixed to every status report, including the one served over HTTP, so a
// scraped stats page identifies which build produced it.
const std::string kBanner = APP_NAME " " APP_VERSION_STR "\r\n\r\n";

std::string statusText(const ReplayStatus& s) {
    if (!s.running) {
        if (s.completed) return kBanner + "Finished: reached the configured duration.";
        return kBanner + (s.error.empty() ? std::string("Idle")
                                          : ("Stopped: " + s.error));
    }
    const PcapSourceStatus& src = s.source;
    char buf[4096];
    std::snprintf(buf, sizeof buf,
        "Format                 : %s\r\n"
        "Sending to  path A     : %s\r\n"
        "            path B     : %s\r\n"
        "Elapsed                : %.1f s\r\n"
        "Frames sent            : %s\r\n"
        "\r\n"
        "-- source ------------------------------------------\r\n"
        "Merge                  : %s\r\n"
        "Frames produced        : %s\r\n"
        "Capture loops          : %s   (early %s)\r\n"
        "Position in capture    : %.1f%%\r\n"
        "Disk read rate         : %.0f Mb/s\r\n"
        "Ring buffer            : %d / %d frames\r\n"
        "Frames repeated        : %s   (ring ran dry %s times)\r\n"
        "Rejected  raster / short / hole : %s / %s / %s\r\n"
        "Sequence holes         : %s\r\n"
        "Filled from blue leg   : %s\r\n"
        "\r\n"
        "-- transmit ----------------------------------------\r\n"
        "Packet rate  target    : %.0f /s\r\n"
        "             achieved  : %.0f /s   (%.1f%%)\r\n"
        "Wire rate per path     : %.0f Mb/s\r\n"
        "Datagrams built        : %s\r\n"
        "\r\n"
        "Timecode  time of day  : %s\r\n"
        "          to midnight  : %s\r\n"
        "ATC packets rewritten  : %d   line CRC: %s\r\n"
        "\r\n"
        "-- faults ------------------------------------------\r\n"
        "Dropped A / B          : %s / %s\r\n"
        "Reordered              : %s\r\n"
        "Duplicated             : %s\r\n"
        "Sequence jumps         : %s\r\n",
        s.formatText.c_str(),
        s.destinationA.c_str(),
        s.destinationB.empty() ? "-  (single leg, ST 2022-6)" : s.destinationB.c_str(),
        s.elapsedSeconds,
        commas(s.frameIndex).c_str(),

        src.merging ? "ST 2022-7, both legs" : "single leg",
        commas(src.framesProduced).c_str(),
        commas(src.loops).c_str(), commas(src.earlyLoops).c_str(),
        src.progress * 100.0,
        src.readMbps,
        src.ringFill, src.ringDepth,
        commas(s.repeatedFrames).c_str(), commas(src.starves).c_str(),
        commas(src.framesRejectedRaster).c_str(),
        commas(src.framesRejectedShort).c_str(),
        commas(src.framesRejectedHole).c_str(),
        commas(src.sequenceHoles).c_str(),
        commas(src.filledFromBlue).c_str(),

        s.targetPps, s.achievedPps,
        s.targetPps > 0 ? 100.0 * s.achievedPps / s.targetPps : 0.0,
        s.wireMbps,
        commas(s.datagrams).c_str(),

        s.rewritingTimecode ? s.tod.c_str() : "(not rewritten)",
        s.rewritingTimecode ? s.countdown.c_str() : "-",
        s.atcPackets,
        s.rewritingTimecode ? (s.crcModelOk ? "rewritten" : "left alone (model mismatch)")
                            : "untouched",

        commas(s.droppedA).c_str(), commas(s.droppedB).c_str(),
        commas(s.reordered).c_str(),
        commas(s.duplicated).c_str(),
        commas(s.seqJumps).c_str());

    std::string out = kBanner + buf;
    if (!s.warning.empty()) out += "\r\n!! " + s.warning + "\r\n";
    return out;
}

// Whether this node is registered, and with which registry, are the first two
// questions anyone asks of a sender that a controller cannot see -- so they get
// a line each and are stated outright, rather than being left to be inferred
// from a state string.
std::string nmosText(const nmos::NmosStatus& n, bool enabled) {
    if (!enabled) return "NMOS off. Tick the box and press Start.";
    if (!n.running) return n.error.empty() ? "NMOS stopped." : ("!! " + n.error);

    std::string s;

    s += std::string("Registered : ") + (n.registered ? "YES" : "no");
    if (n.registered) {
        s += "   heartbeats " + commas(n.heartbeats);
        if (n.lastHeartbeatAgo >= 0.0) {
            char age[32];
            std::snprintf(age, sizeof age, "%.0fs ago", n.lastHeartbeatAgo);
            s += ", last " + std::string(age);
        }
    }
    if (n.heartbeatFailures) s += "   failures " + commas(n.heartbeatFailures);
    s += "\r\n";

    // Where. Only meaningful once a registry has been settled on, so say so
    // plainly when there is not one rather than printing an empty field.
    s += "Registry   : ";
    if (!n.registryUrl.empty()) {
        s += n.registryUrl;
        if (!n.registryDiscovery.empty()) {
            s += "   (via " + n.registryDiscovery;
            if (!n.registryServiceType.empty()) s += " " + n.registryServiceType;
            s += ")";
        }
    } else {
        s += "none yet   -- " + n.registryState;
    }
    s += "\r\n";
    if (!n.registryUrl.empty()) s += "State      : " + n.registryState + "\r\n";

    s += "Node API   : " + n.nodeApiUrl + "\r\n";
    s += std::string("Sender     : ") + (n.masterEnable ? "enabled" : "disabled");
    if (!n.connectedReceiverId.empty()) s += "   routed to " + n.connectedReceiverId;
    s += n.advertising ? "   (advertising peer-to-peer)" : "";
    s += "\r\n";
    s += "Sender id  : " + n.senderId + "\r\n";
    if (!n.groupHint.empty()) s += "Group hint : " + n.groupHint + "\r\n";

    if (!n.lastActivation.empty()) s += "Last IS-05 : " + n.lastActivation + "\r\n";

    // Discovery. Shown even when a registry has been found, because "browsing
    // these types, found these" is what settles an argument about whether mDNS
    // is working on the segment.
    if (n.browsing || !n.browsedServiceTypes.empty()) {
        s += "mDNS       : browsing ";
        for (std::size_t i = 0; i < n.browsedServiceTypes.size(); ++i)
            s += (i ? ", " : "") + n.browsedServiceTypes[i];
        if (!n.browsing) s += "   (stopped)";
        s += "\r\n";
    }
    if (!n.discoveredRegistries.empty()) {
        s += "Found      : ";
        for (std::size_t i = 0; i < n.discoveredRegistries.size(); ++i)
            s += (i ? "\r\n             " : "") + n.discoveredRegistries[i];
        s += "\r\n";
    } else if (n.browsing) {
        s += "Found      : no registry advertised on this segment yet\r\n";
    }

    if (!n.mdnsRejection.empty()) s += "!! " + n.mdnsRejection + "\r\n";
    if (!n.mdnsError.empty())     s += "!! mDNS: " + n.mdnsError + "\r\n";
    if (!n.warning.empty())       s += "!! " + n.warning + "\r\n";
    if (!n.error.empty())         s += "!! " + n.error + "\r\n";
    return s;
}

// ---- dialog ----------------------------------------------------------------

INT_PTR CALLBACK dlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));

    switch (msg) {
    case WM_INITDIALOG: {
        app = reinterpret_cast<App*>(lp);
        SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);

        SetWindowTextW(dlg, widen(APP_NAME " " APP_VERSION_STR
                                  "  -  ST 2022-6/-7 source with NMOS").c_str());

        fillInterfaces(dlg, *app);

        // Which instance this is, and therefore which settings file, which node
        // port and which stats port. Must happen before anything is read.
        const InstanceSlot slot = resolveInstanceSlot();
        app->slot = slot;
        app->settings.emplace(slot.settingsName, slot.index != 0);
        if (slot.index != 0)
            SetWindowTextW(dlg, widen(APP_NAME " " APP_VERSION_STR
                                      "  -  instance " + std::to_string(slot.index + 1) +
                                      "  -  ST 2022-6/-7 source with NMOS").c_str());

        auto& st = *app->settings;
        setText(dlg, IDC_RED,  st.getString("red", ""));
        setText(dlg, IDC_BLUE, st.getString("blue", ""));
        SetDlgItemInt(dlg, IDC_RING, UINT(st.getInt("ring", 16)), FALSE);
        SetDlgItemInt(dlg, IDC_SKIP, UINT(st.getInt("skip", 10)), FALSE);

        const bool seven = st.getBool("seven", true);
        check(dlg, seven ? IDC_MODE_7 : IDC_MODE_6, true);
        setText(dlg, IDC_A_GROUP, st.getString("a_group", "239.1.1.1"));
        SetDlgItemInt(dlg, IDC_A_PORT, UINT(st.getInt("a_port", 40000)), FALSE);
        selectIface(dlg, *app, IDC_A_IFACE, st.getString("a_iface", ""));
        setText(dlg, IDC_B_GROUP, st.getString("b_group", "239.2.1.1"));
        SetDlgItemInt(dlg, IDC_B_PORT, UINT(st.getInt("b_port", 40000)), FALSE);
        selectIface(dlg, *app, IDC_B_IFACE, st.getString("b_iface", ""));
        SetDlgItemInt(dlg, IDC_TTL, UINT(st.getInt("ttl", 8)), FALSE);
        check(dlg, IDC_LOOPBACK, st.getBool("loopback", true));
        check(dlg, IDC_TIMECODE, st.getBool("timecode", true));
        SetDlgItemInt(dlg, IDC_DURATION, UINT(st.getInt("duration", 0)), FALSE);
        setText(dlg, IDC_F_RATE, "0.1");

        check(dlg, IDC_NMOS_EN, st.getBool("nmos", false));
        setText(dlg, IDC_NMOS_LABEL, st.getString("nmos_label", "PCAP Replay"));
        // Not inherited: this is the value that makes the instance distinct, so
        // a second copy opens on 3211 rather than on the first one's 3210, which
        // it would immediately have to move off anyway.
        SetDlgItemInt(dlg, IDC_NMOS_PORT,
                      UINT(st.getIntOwn("nmos_port", slot.nodePort)), FALSE);
        selectIface(dlg, *app, IDC_NMOS_IFACE, st.getString("nmos_iface", ""));
        const bool useMdns = st.getBool("nmos_mdns", true);
        check(dlg, useMdns ? IDC_NMOS_MDNS : IDC_NMOS_MANUAL, true);
        setText(dlg, IDC_NMOS_HOST, st.getString("nmos_host", ""));
        SetDlgItemInt(dlg, IDC_NMOS_RPORT, UINT(st.getInt("nmos_rport", 3210)), FALSE);
        check(dlg, IDC_NMOS_P2P, st.getBool("nmos_p2p", true));

        updateModeUi(dlg, false);
        updateNmosUi(dlg);
        describeFiles(dlg, *app);

        {
            std::lock_guard<std::mutex> lk(app->controlMutex);
            app->cfg = configFrom(dlg, *app);
        }
        startNmos(dlg, *app);

        // The scraped page carries the NMOS block too, so a report gathered from
        // a machine nobody is sitting at still says whether the node registered
        // and with which registry.
        // Step to the next free port, for the same reason the NMOS node does: a
        // second instance on this machine should still get a stats page rather
        // than losing its only scriptable surface to the first one.
        auto provider = [app] {
            return statusText(app->engine.status()) +
                   "\r\n-- nmos --------------------------------------------\r\n" +
                   nmosText(app->nmos->status(),
                            app->nmosEnabled.load(std::memory_order_relaxed));
        };
        std::uint16_t statsPort = app->slot.statsPort;
        for (int i = 0; i < 20; ++i) {
            const auto p = std::uint16_t(app->slot.statsPort + i);
            if (app->stats.start(p, provider)) { statsPort = p; break; }
        }
        setText(dlg, IDC_STATSURL,
                app->stats.running()
                    ? "Live stats: http://127.0.0.1:" +
                          std::to_string(statsPort) + "/"
                    : "Stats server unavailable: " + app->stats.error());

        SetTimer(dlg, kTimerStatus, 250, nullptr);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_RED_BROWSE:  doBrowse(dlg, *app, IDC_RED);  return TRUE;
        case IDC_BLUE_BROWSE: doBrowse(dlg, *app, IDC_BLUE); return TRUE;
        case IDC_RED:
        case IDC_BLUE:
            if (HIWORD(wp) == EN_KILLFOCUS) describeFiles(dlg, *app);
            return TRUE;
        case IDC_RING:
            if (HIWORD(wp) == EN_KILLFOCUS) describeFiles(dlg, *app);
            return TRUE;
        case IDC_MODE_6:
        case IDC_MODE_7:
            updateModeUi(dlg, app->engine.running());
            return TRUE;

        case IDC_NMOS_EN:
        case IDC_NMOS_MDNS:
        case IDC_NMOS_MANUAL:
            updateNmosUi(dlg);
            startNmos(dlg, *app);
            return TRUE;
        case IDC_NMOS_P2P:
            startNmos(dlg, *app);
            return TRUE;

        case IDC_START:
            if (app->engine.running()) doStop(dlg, *app);
            else                       doStart(dlg, *app);
            return TRUE;

        // Impairments can be toggled while running; the engine re-reads them
        // only on start, so flipping one restarts it with the new set. That is
        // cheap because the capture is streamed, not reloaded.
        case IDC_F_LOSS_A: case IDC_F_LOSS_B: case IDC_F_BURST:
        case IDC_F_REORDER: case IDC_F_DUP: case IDC_F_SEQJUMP:
            if (app->engine.running()) {
                const ReplayConfig cfg = configFrom(dlg, *app);
                std::lock_guard<std::mutex> lk(app->controlMutex);
                app->cfg = cfg;
                app->engine.start(cfg);
            }
            return TRUE;

        case IDCANCEL:
            app->nmos->stop();
            app->engine.stop();
            app->stats.stop();
            EndDialog(dlg, 0);
            return TRUE;
        }
        return FALSE;

    case WM_TIMER:
        if (wp == kTimerStatus && app) {
            const ReplayStatus s = app->engine.status();
            setText(dlg, IDC_STATUS, statusText(s));

            std::string summary;
            if (s.running)        summary = s.formatText + "   running";
            else if (s.completed) summary = "Finished";
            else if (!s.error.empty()) summary = "Stopped";
            else                  summary = "Idle";
            if (s.running && s.repeatedFrames)
                summary += "   -   disk not keeping up";
            setText(dlg, IDC_SUMMARY, summary);

            setText(dlg, IDC_NMOS_STATUS,
                    nmosText(app->nmos->status(), checked(dlg, IDC_NMOS_EN)));

            // The engine can stop on its own -- a duration cap, or a fatal
            // source error -- and IS-05 can start or stop it behind the GUI's
            // back, so the buttons follow the engine rather than the last click.
            const bool running = s.running;
            const bool shown = GetWindowTextLengthW(GetDlgItem(dlg, IDC_START)) == 4;
            bool dirty = false, fields = false;
            ReplayConfig cur;
            {
                std::lock_guard<std::mutex> lk(app->controlMutex);
                dirty = app->uiDirty;
                fields = app->fieldsDirty;
                app->uiDirty = false;
                app->fieldsDirty = false;
                cur = app->cfg;
            }
            if (fields) setTransmitFields(dlg, cur);
            if (shown != running || dirty) setRunningUi(dlg, running);
        }
        return TRUE;

    case WM_CLOSE:
        app->nmos->stop();
        app->engine.stop();
        app->stats.stop();
        EndDialog(dlg, 0);
        return TRUE;
    }
    return FALSE;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int) {
    INITCOMMONCONTROLSEX icc{sizeof icc, ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    App app;
    DialogBoxParamW(inst, MAKEINTRESOURCEW(IDD_REPLAY), nullptr, dlgProc,
                    reinterpret_cast<LPARAM>(&app));
    return 0;
}
