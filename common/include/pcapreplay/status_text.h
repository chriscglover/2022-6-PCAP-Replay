// The status panel, rendered as text.
//
// One renderer, three consumers: the Win32 dialog, the loopback stats endpoint
// and the CLI's periodic report. They were three copies of the same snprintf
// before the CLI grew a stats server of its own, which is one copy too many for
// something whose whole job is to be believed -- a panel that says something
// different depending on where you read it is worse than no panel.
//
// The banner is deliberately not included: it carries APP_NAME and the version
// out of app/resource.h, which is not visible from here, so the caller prepends
// it. That is also what lets the CLI print a report with no banner every two
// seconds while serving a bannered one over HTTP.
#pragma once

#include <string>

#include "pcapreplay/replay_engine.h"

namespace pcapreplay {

// `eol` is "\r\n" for a Win32 edit control, which will not render a bare
// newline, and "\n" for a terminal or curl.
std::string statusText(const ReplayStatus& s, const char* eol = "\r\n");

// Thousands separators. Frame and datagram counts run to ten digits within an
// hour, and an unseparated ten-digit number cannot be read at a glance.
std::string commas(std::uint64_t v);

}  // namespace pcapreplay
