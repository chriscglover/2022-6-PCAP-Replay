#include "pcapreplay/settings.h"

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#endif

#include <vector>

namespace pcapreplay {

#ifdef _WIN32

namespace {

constexpr const wchar_t* kSection = L"config";

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
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), s.data(), n,
                        nullptr, nullptr);
    return s;
}

}  // namespace

Settings::Settings(const std::string& app) {
    PWSTR roaming = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &roaming))) {
        std::wstring dir = roaming;
        CoTaskMemFree(roaming);
        dir += L"\\PCAP Replay";
        CreateDirectoryW(dir.c_str(), nullptr);
        // The profile API needs an absolute path or it writes into the Windows
        // directory.
        path_ = narrow(dir + L"\\" + widen(app) + L".ini");
    }
}

std::string Settings::getString(const char* key, const std::string& fallback) const {
    if (path_.empty()) return fallback;
    wchar_t buf[1024] = {};
    GetPrivateProfileStringW(kSection, widen(key).c_str(), widen(fallback).c_str(),
                             buf, 1024, widen(path_).c_str());
    return narrow(buf);
}

void Settings::setString(const char* key, const std::string& value) {
    if (path_.empty()) return;
    WritePrivateProfileStringW(kSection, widen(key).c_str(), widen(value).c_str(),
                               widen(path_).c_str());
}

int Settings::getInt(const char* key, int fallback) const {
    if (path_.empty()) return fallback;
    return int(GetPrivateProfileIntW(kSection, widen(key).c_str(), fallback,
                                     widen(path_).c_str()));
}

#else   // POSIX

// There is no profile API to lean on, so the INI is parsed here. It is a
// deliberately small format -- one [config] section, key=value, # or ; for a
// comment -- because it has to interoperate with files the Windows build wrote,
// and because a settings file someone can fix in an editor is worth more than
// one that needs a tool.
//
// Reads parse the whole file each time. It is a few hundred bytes read at
// startup and on the odd write, not something on a hot path, and the
// alternative -- an in-memory cache -- gets stale the moment two instances share
// a file, which is precisely what the instance-slot logic sets up.

namespace {

std::string configDir() {
    // XDG first, ~/.config as the specified fallback. Both spellings of the
    // app directory are lower case and hyphenated, which is what a Linux user
    // expects to find under ~/.config -- not the Windows "PCAP Replay".
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg)
        return std::string(xdg) + "/pcap-replay";
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::string(home) + "/.config/pcap-replay";
    return {};
}

// mkdir -p for the two levels this needs. Not a general implementation: the
// parent is either $XDG_CONFIG_HOME or ~/.config, both of which the caller has
// by definition, so only the last component is ever genuinely missing.
bool ensureDir(const std::string& path) {
    if (path.empty()) return false;
    const std::size_t slash = path.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        const std::string parent = path.substr(0, slash);
        struct stat st{};
        if (stat(parent.c_str(), &st) != 0) mkdir(parent.c_str(), 0755);
    }
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    return mkdir(path.c_str(), 0700) == 0;
}

std::string trim(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' ||
                     s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// Every key/value in the [config] section, in file order. Order is kept so a
// rewrite does not shuffle a file someone has been reading.
std::vector<std::pair<std::string, std::string>> readAll(const std::string& path) {
    std::vector<std::pair<std::string, std::string>> out;
    std::ifstream in(path);
    if (!in) return out;

    bool inSection = false;
    std::string line;
    while (std::getline(in, line)) {
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        if (t.front() == '[') {
            inSection = (t == "[config]");
            continue;
        }
        if (!inSection) continue;
        const std::size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        out.emplace_back(trim(t.substr(0, eq)), trim(t.substr(eq + 1)));
    }
    return out;
}

// Written to a temporary and renamed, so a crash or a full disk part way
// through cannot leave a half-written settings file where a whole one was.
bool writeAll(const std::string& path,
              const std::vector<std::pair<std::string, std::string>>& kv) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return false;
        out << "[config]\n";
        for (const auto& e : kv) out << e.first << "=" << e.second << "\n";
        if (!out) return false;
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

}  // namespace

Settings::Settings(const std::string& app) {
    const std::string dir = configDir();
    if (dir.empty() || !ensureDir(dir)) return;
    path_ = dir + "/" + app + ".ini";
}

std::string Settings::getString(const char* key, const std::string& fallback) const {
    if (path_.empty()) return fallback;
    for (const auto& e : readAll(path_))
        if (e.first == key) return e.second;
    return fallback;
}

void Settings::setString(const char* key, const std::string& value) {
    if (path_.empty()) return;
    auto kv = readAll(path_);
    for (auto& e : kv) {
        if (e.first == key) { e.second = value; writeAll(path_, kv); return; }
    }
    kv.emplace_back(key, value);
    writeAll(path_, kv);
}

int Settings::getInt(const char* key, int fallback) const {
    const std::string s = getString(key, {});
    if (s.empty()) return fallback;
    // strtol rather than atoi so a non-numeric value falls back rather than
    // silently reading as zero -- a port number of 0 means "ephemeral" here, so
    // getting one by accident is not harmless.
    char* end = nullptr;
    const long v = std::strtol(s.c_str(), &end, 10);
    if (end == s.c_str()) return fallback;
    return int(v);
}

#endif   // _WIN32

// Shared across both platforms: these are only ever expressed in terms of the
// two primitives above.
bool Settings::getBool(const char* key, bool fallback) const {
    return getInt(key, fallback ? 1 : 0) != 0;
}

void Settings::setInt(const char* key, int value) {
    setString(key, std::to_string(value));
}

void Settings::setBool(const char* key, bool value) { setInt(key, value ? 1 : 0); }

}  // namespace pcapreplay
