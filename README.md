# PCAP Replay

Turn a packet capture of an ST 2022-6 stream into a continuous, endlessly
looping ST 2022-6/-7 source that an NMOS controller can route like any other
piece of broadcast kit.

Built on the replay engine from the NDI2022-6 rig, with three changes:

1. **The source is a pcap**, not an extracted `.sdi` raster. Give it both legs of
   an ST 2022-7 pair and they are merged, so a datagram lost on one leg is
   filled from the other. Captures are **streamed off disk through a small ring
   buffer**, so a multi-gigabyte file plays in full rather than only as much of
   it as fits in RAM.
2. **NMOS**: the app registers as an IS-04 sender, serves IS-05 so a controller
   can activate it and change its destination, and publishes an SDP manifest.
3. **No NDI at all** — no SDK to build against and no runtime DLL to ship.

Everything the original replay did still works: indefinite looping with fresh
RTP and HBRMT headers so the loop join is invisible, live timecode rewriting,
and random impairments for exercising a receiver.

Deployment is one `.exe`. No Conan, no vcpkg, no Bonjour SDK, no .NET, no GPU.

## Status

**Validated end to end against a real NMOS system**: a captured ST 2022-7 pair
replayed from disk, registered with a live registry, listed in NMOS Explorer,
routed by a controller to a hardware ST 2022-6 receiver, and decoded.

| Component | State |
|-----------|-------|
| pcap ingest, format detection, marker-bit frame cutting, raster validation | ✅ Proven on 1080i25 and 625i25 captures |
| ST 2022-7 two-leg merge | ✅ Proven — recovers datagrams missing from one leg |
| Streaming ring buffer at line rate | ✅ Proven — 129 fps merged against 25 fps needed |
| Loop, fresh RTP/HBRMT, timecode rewrite, fault injection | ✅ Carried over from NDI2022-6, unchanged |
| IS-04 registration, heartbeat, Node API | ✅ Proven against a live registry |
| IS-05 connection API, activation, destination change | ✅ Proven — routed by a controller |
| SDP manifest, incl. `a=group:DUP` for the -7 pair | ✅ Proven — accepted by a hardware receiver |
| mDNS registry discovery / peer-to-peer advertisement | ⚠️ Written; registry override path is the one exercised |
| Scheduled IS-05 activation | ❌ Returns 501; only `activate_immediate` |
| Long-run registry garbage-collection recovery | ⚠️ 404-triggered re-registration written, not yet exercised over hours |

## Quick start

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
.\build\bin\pcap_replay.exe
```

Pick a red capture, optionally a blue one, choose the multicast groups and the
NIC for each path, and press Start.

## Why re-originate rather than replay the packets

A verbatim packet replay has to jump its RTP sequence number, RTP timestamp,
SSRC and HBRMT frame counter backwards at every loop, and a receiver reads all
four of those as a fault. This app decodes the capture back to the SDI raster
and generates the headers itself, so the loop join is invisible and the stream
runs indefinitely.

The raster is copied through untouched apart from the timecode rewrite, so the
replay still carries everything the original broadcast did — ATC timecode, OP-47
subtitles, SCTE 104, AFD, ST 2020 metadata and 16 channels of ST 299 audio.

## How the streaming source works

Per frame, on a background thread:

1. **Merge.** Take the next datagram in RTP sequence order from the red leg, or
   from the blue leg if red has not got it. That is the ST 2022-7 merge. With
   one file it degrades to a plain read.
2. **Cut frames on the RTP marker bit**, not by locking the raster. Real
   broadcast kit zero-pads the last datagram of a frame — 1080i25 sends
   5397 × 1376 = 7,426,272 bytes for a 7,425,000-byte raster — so the 10-bit
   byte phase shifts by 1272 mod 5 = 2 at every frame boundary and a
   continuous-raster reader loses lock every frame. Keying on the marker
   sidesteps it, and each frame then starts at byte phase 0.
3. **Validate the raster** — EAV on every line, and the line number on HD —
   before the frame is allowed into the ring.

Frames that fail, or that have a sequence hole neither leg could fill, are
dropped and the next one is tried. After `skipTolerance` consecutive failures
(default 10) the capture is treated as exhausted at that point: both readers
rewind, the loop restarts early, and a warning appears in the GUI.

**If the ring runs dry the transmitter repeats the current frame** rather than
stalling. A gap on the wire reads to a receiver as a fault, whereas a repeated
frame keeps the packet rate and RTP sequence continuous. The repeat count is
shown, so "the disk is not keeping up" stays visible rather than silent.

### Does the disk keep up?

Measured on the reference 1080i25 `-7` pair, ring depth 16:

| Source | Frames/s produced | Needed |
|--------|-------------------|--------|
| red + blue merged | **129** | 25 |
| red only | **215** | 25 |

Five times real time with both legs, so there is ample headroom. Use
`replay_cli --ingest N` to measure it for your own capture and disk.

## NMOS

| Spec | What is implemented |
|------|---------------------|
| IS-04 v1.3 | Registration and heartbeat; Node API serving self, device, source, flow, sender |
| IS-05 v1.1 | `constraints`, `staged`, `active`, `transportfile`, `transporttype`, and `bulk/senders` |
| Discovery | mDNS browse for `_nmos-register._tcp`, with a manual host/port override |
| Peer-to-peer | Advertises `_nmos-node._tcp`, so a controller can find the node with no registry present |

ST 2022-6 carries a whole SDI signal, so it is modelled as a **mux**: the source
and flow are `urn:x-nmos:format:mux`, the flow's `media_type` is
`video/SMPTE2022-6`, and the sender's transport is
`urn:x-nmos:transport:rtp.mcast`. This was checked against a dump of a
third-party broadcast ST 2022-6 sender.

Resource UUIDs are **deterministic** (UUID v5 over the machine name and the
resource role), so they survive a restart and a controller's existing route
still points at something that exists.

### The SDP

A `-7` pair is two `m=` lines grouped per RFC 7104, which is how a receiver is
told the two legs are copies of each other rather than two different essences:

```
v=0
o=- 1990966629 450267930 IN IP4 192.168.0.1
s=PCAP Replay
i=1080i25 (1080i50)  1920x1080  1.485 Gb/s
t=0 0
a=group:DUP primary secondary
m=video 40000 RTP/AVP 98
c=IN IP4 239.0.0.1/8
a=source-filter: incl IN IP4 239.0.0.1 192.168.0.1
a=rtpmap:98 SMPTE2022-6/27000000
a=fmtp:98 TP=2110TPW;
a=ts-refclk:localmac=02-00-5e-00-00-01
a=mediaclk:direct=0
a=mid:primary
m=video 40000 RTP/AVP 98
c=IN IP4 239.0.0.2/8
a=source-filter: incl IN IP4 239.0.0.2 192.168.0.2
a=rtpmap:98 SMPTE2022-6/27000000
a=fmtp:98 TP=2110TPW;
a=ts-refclk:localmac=02-00-5e-00-00-02
a=mediaclk:direct=0
a=mid:secondary
```

Addresses above are illustrative. Two deliberate departures from the reference
sender:

- **`ts-refclk:localmac`, not `ptp=IEEE1588-2008:traceable`.** This machine is
  not locked to PTP. Claiming a traceable PTP reference we do not have would
  make a receiver's timing decisions wrong rather than merely conservative.
- **`TP=2110TPW` with no `TROFF`.** The pacer places every datagram against an
  absolute QPC schedule rather than bursting a frame at line rate, so the wide
  traffic profile is an honest description. `TROFF` is an offset from a PTP
  epoch, and there is no PTP epoch here to offset from.

### Limitations

- **Only `activate_immediate`.** Scheduled activation returns `501`. Controllers
  in normal use activate immediately.
- **`source_ip` is fixed** by the NIC chosen in the GUI, published as a
  single-value `enum`. A PATCH asking for a different one is rejected rather
  than silently ignored.
- No IS-05 receivers — this app only sends.
- No TLS and no IS-10 authorization; `http` only.

## Command line

`replay_cli` drives the same engines without the dialog, for scripting and
measurement.

```powershell
# what is in these captures?
.\build\bin\replay_cli.exe red.pcap blue.pcap --probe

# can the disk sustain line rate?
.\build\bin\replay_cli.exe red.pcap blue.pcap --ingest 30

# where does a capture's RTP sequence actually jump?
.\build\bin\replay_cli.exe red.pcap --gaps

# print the SDP a controller would fetch
.\build\bin\replay_cli.exe red.pcap blue.pcap --group 239.1.1.1 --group-b 239.2.1.1 --sdp

# replay a -7 pair with NMOS, for 60 seconds
.\build\bin\replay_cli.exe red.pcap blue.pcap `
    --group 239.0.0.1 --group-b 239.0.0.2 --iface 192.168.0.1 `
    --seconds 60 --nmos --registry 10.0.0.5:3210
```

## Reading a capture's health

`--gaps` walks a capture packet by packet and reports every RTP sequence
discontinuity, independently of the merge. It is the way to tell a damaged
capture from a reader bug. On the reference pair, both legs turn out to have
exactly one discontinuity, at the same instant, near the start:

```
gap 1: after packet 820, seq 52206 -> 54339 (2132 missing)
1312407 datagrams, 1 discontinuities, 2132 missing datagrams
243 markers; first marker at packet 5772
```

That is a capture-buffer overrun as the recording started. It costs no frames,
because it lands before the first frame marker — which is why the status panel
can show thousands of sequence holes and zero rejected frames at the same time.

## Live stats

`http://127.0.0.1:49610/` returns the same panel as the GUI, in plain text, for
scripting. Loopback only.

Port 49610, not the 49603 the NDI2022-6 replay used: that rig is routinely
running on the same machine and the two would otherwise fight over the port.

## Supported formats

1080i25/29.97/30 · 1080p25/29.97/30/50/59.94/60 · 1080PsF25 · 720p50/59.94/60 ·
625i25 · 525i29.97, all 4:2:2 10-bit.

Captures must be **classic pcap**, not pcapng. Ethernet, raw IPv4, Linux SLL and
NULL/loopback link types are all handled.

## Layout

| Path | What is in it |
|------|---------------|
| `common/` | SDI format tables, 10-bit packing, CRC, HBRMT/RTP, multicast, pacer, the pcap source and the replay engine |
| `nmos/` | JSON, HTTP server and client, DNS-SD, and the IS-04/IS-05 node |
| `app/` | the Win32 dialog |
| `tools/` | `replay_cli` |

`common/` is NDI2022-6's `st2022_common` with the NDI-facing half removed and
the namespace renamed to `pcapreplay`.

The NMOS layer is hand-rolled rather than sony/nmos-cpp, so the app stays a
single executable: nmos-cpp has no vcpkg port, its `cpprestsdk` and `websocketpp`
dependencies have both been **removed from vcpkg**, and its supported build path
is now Conan. `NmosBackend` in `nmos/include/pcapreplay/nmos/nmos_node.h` is the
seam — adding an nmos-cpp backend means another implementation of that
interface, not a rewrite of the app.

## Licence

MIT — see [LICENSE](LICENSE).

The whole thing is first-party: there are no bundled third-party sources and no
libraries to link beyond the Windows SDK (`ws2_32`, `iphlpapi`, `winmm`,
`dnsapi`, `comctl32`), so there is nothing else whose terms you have to satisfy.
That is a large part of why the NMOS layer is hand-rolled.

## A note on captured media

`.pcap`, `.sdi` and `.wav` files are gitignored: they contain off-air broadcast
content. So is `docs/reference/nmos_capture_*`, which is a dump of a real
broadcaster's NMOS node and carries their identifiers, multicast plan and
network addressing.
