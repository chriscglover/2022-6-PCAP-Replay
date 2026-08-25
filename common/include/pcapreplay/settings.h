// Per-application settings, persisted to an INI beside the user's profile.
//
// One [config] section of key=value, which is what the Win32 profile API writes
// and what the POSIX build parses, so a file is readable by either. Writes are
// immediate.
//
//   Windows   %APPDATA%\PCAP Replay\<app>.ini
//   Linux     $XDG_CONFIG_HOME/pcap-replay/<app>.ini,
//             or ~/.config/pcap-replay/<app>.ini
#pragma once

#include <string>

namespace pcapreplay {

class Settings {
public:
    // `app` names the file, e.g. "sender".
    explicit Settings(const std::string& app);

    std::string getString(const char* key, const std::string& fallback) const;
    int         getInt(const char* key, int fallback) const;
    bool        getBool(const char* key, bool fallback) const;

    void setString(const char* key, const std::string& value);
    void setInt(const char* key, int value);
    void setBool(const char* key, bool value);

    const std::string& path() const { return path_; }
    bool usable() const { return !path_.empty(); }

private:
    std::string path_;
};

}  // namespace pcapreplay
