#include "pcapreplay/status_text.h"

#include <cstdio>

namespace pcapreplay {

std::string commas(std::uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(std::size_t(i), ",");
    return s;
}

std::string statusText(const ReplayStatus& s, const char* eol) {
    if (!s.running) {
        if (s.completed) return "Finished: reached the configured duration.";
        return s.error.empty() ? std::string("Idle") : ("Stopped: " + s.error);
    }

    const PcapSourceStatus& src = s.source;
    char buf[4096];
    std::snprintf(buf, sizeof buf,
        "Format                 : %s%s"
        "Sending to  path A     : %s%s"
        "            path B     : %s%s"
        "Elapsed                : %.1f s%s"
        "Frames sent            : %s%s"
        "%s"
        "-- source ------------------------------------------%s"
        "Merge                  : %s%s"
        "Frames produced        : %s%s"
        "Capture loops          : %s   (early %s)%s"
        "Position in capture    : %.1f%%%s"
        "Disk read rate         : %.0f Mb/s%s"
        "Ring buffer            : %d / %d frames%s"
        "Frames repeated        : %s   (ring ran dry %s times)%s"
        "Rejected  raster / short / hole : %s / %s / %s%s"
        "Sequence holes         : %s%s"
        "Filled from blue leg   : %s%s"
        "%s"
        "-- transmit ----------------------------------------%s"
        "Packet rate  target    : %.0f /s%s"
        "             achieved  : %.0f /s   (%.1f%%)%s"
        "Wire rate per path     : %.0f Mb/s%s"
        "Datagrams built        : %s%s"
        "%s"
        "Timecode  time of day  : %s%s"
        "          to midnight  : %s%s"
        "ATC packets rewritten  : %d   line CRC: %s%s"
        "%s"
        "-- faults ------------------------------------------%s"
        "Dropped A / B          : %s / %s%s"
        "Reordered              : %s%s"
        "Duplicated             : %s%s"
        "Sequence jumps         : %s%s",
        s.formatText.c_str(), eol,
        s.destinationA.c_str(), eol,
        s.destinationB.empty() ? "-  (single leg, ST 2022-6)" : s.destinationB.c_str(), eol,
        s.elapsedSeconds, eol,
        commas(s.frameIndex).c_str(), eol,
        eol,
        eol,
        src.merging ? "ST 2022-7, both legs" : "single leg", eol,
        commas(src.framesProduced).c_str(), eol,
        commas(src.loops).c_str(), commas(src.earlyLoops).c_str(), eol,
        src.progress * 100.0, eol,
        src.readMbps, eol,
        src.ringFill, src.ringDepth, eol,
        commas(s.repeatedFrames).c_str(), commas(src.starves).c_str(), eol,
        commas(src.framesRejectedRaster).c_str(),
        commas(src.framesRejectedShort).c_str(),
        commas(src.framesRejectedHole).c_str(), eol,
        commas(src.sequenceHoles).c_str(), eol,
        commas(src.filledFromBlue).c_str(), eol,
        eol,
        eol,
        s.targetPps, eol,
        s.achievedPps,
        s.targetPps > 0 ? 100.0 * s.achievedPps / s.targetPps : 0.0, eol,
        s.wireMbps, eol,
        commas(s.datagrams).c_str(), eol,
        eol,
        s.rewritingTimecode ? s.tod.c_str() : "(not rewritten)", eol,
        s.rewritingTimecode ? s.countdown.c_str() : "-", eol,
        s.atcPackets,
        s.rewritingTimecode ? (s.crcModelOk ? "rewritten" : "left alone (model mismatch)")
                            : "untouched", eol,
        eol,
        eol,
        commas(s.droppedA).c_str(), commas(s.droppedB).c_str(), eol,
        commas(s.reordered).c_str(), eol,
        commas(s.duplicated).c_str(), eol,
        commas(s.seqJumps).c_str(), eol);

    std::string out = buf;
    if (!s.warning.empty()) out += std::string(eol) + "!! " + s.warning + eol;
    return out;
}

}  // namespace pcapreplay
