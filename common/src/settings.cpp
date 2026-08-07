#include "pcapreplay/settings.h"

#include <windows.h>
#include <shlobj.h>

#include <vector>

namespace pcapreplay {
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

int Settings::getInt(const char* key, int fallback) const {
    if (path_.empty()) return fallback;
    return int(GetPrivateProfileIntW(kSection, widen(key).c_str(), fallback,
                                     widen(path_).c_str()));
}

bool Settings::getBool(const char* key, bool fallback) const {
    return getInt(key, fallback ? 1 : 0) != 0;
}

void Settings::setString(const char* key, const std::string& value) {
    if (path_.empty()) return;
    WritePrivateProfileStringW(kSection, widen(key).c_str(), widen(value).c_str(),
                               widen(path_).c_str());
}

void Settings::setInt(const char* key, int value) {
    setString(key, std::to_string(value));
}

void Settings::setBool(const char* key, bool value) { setInt(key, value ? 1 : 0); }

}  // namespace pcapreplay
