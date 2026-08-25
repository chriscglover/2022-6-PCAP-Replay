# PCAP Replay

Turn a packet capture of an ST 2022-6 stream into a continuous, endlessly
looping ST 2022-6/-7 source that an NMOS controller can route like any other
piece of broadcast kit.

Built on an earlier ST 2022-6 replay engine, with two changes:

1. **The source is a pcap**, not an extracted `.sdi` raster. Give it both legs of
   an ST 2022-7 pair and they are merged, so a datagram lost on one leg is
   filled from the other. Captures are **streamed off disk through a small ring
   buffer**, so a multi-gigabyte file plays in full rather than only as much of
   it as fits in RAM.
2. **NMOS**: the app registers as an IS-04 sender, serves IS-05 so a controller
   can activate it and change its destination, and publishes an SDP manifest.

Everything the original replay did still works: indefinite looping with fresh
RTP and HBRMT headers so the loop join is invisible, live timecode rewriting,
and random impairments for exercising a receiver.

Runs on **Windows** as a dialog application and on **Linux** as a command line
tool, from one codebase. Deployment is one binary either way. No Conan, no
vcpkg, no Bonjour SDK, no Avahi, no libpcap, no .NET, no GPU.

## Requirements

**Windows — copy `pcap_replay.exe` and double-click it. Linux — copy
`replay_cli` and run it.** There is nothing to install on either.

| | |
|---|---|
| Visual C++ Redistributable | **Not needed.** Linked against the static CRT (`/MT`), so there is no `VCRUNTIME140.dll` or `MSVCP140.dll` to ship. |
| .NET | **Not needed.** Native C++ throughout. |
| Bonjour / mDNSResponder | **Not needed.** DNS-SD uses the Windows API in `dnsapi.dll`, not Apple's SDK or service. |
| OS | Windows 10 version 1703 or later, x64 — the floor is `DnsServiceBrowse`/`DnsServiceRegister`, which arrived in 1703. Or Linux on x86-64: kernel 3.9+ for `SO_REUSEPORT`, and 4.18+ to get segmentation offload, which is probed at runtime and not required. |
| CPU | Any x64. AVX2 is used for the 10-bit packing hot loops but is probed at runtime with a scalar fallback, so it is not required. |
| Disk | Fast enough to stream the capture. 1080i25 needs ~190 MB/s per leg, so ~380 MB/s for a `-7` pair. Any NVMe is comfortable; measure yours with `replay_cli --ingest`. |

On Windows the only libraries linked are Windows SDK ones — `ws2_32`,
`iphlpapi`, `winmm`, `dnsapi`, `comctl32` — all present on any Windows install.
`dumpbin /dependents` on the shipped binary lists nothing else.

On Linux the only libraries linked are libc, libstdc++ and libpthread:

```
$ ldd build/bin/replay_cli
    linux-vdso.so.1
    libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6
    libgcc_s.so.1  => /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
    libc.so.6      => /usr/lib/x86_64-linux-gnu/libc.so.6
    libm.so.6      => /usr/lib/x86_64-linux-gnu/libm.so.6
```

No libpcap — the capture reader is first-party. No Avahi and no D-Bus — see
[DNS-SD without a daemon](#dns-sd-without-a-daemon). That is what lets this run
in a container with nothing else in it, which is where most NMOS nodes live.

**To build on Windows** you need Visual Studio 2022 or later with the C++
workload, and CMake 3.24+. Visual Studio's bundled CMake is sufficient.

**To build on Linux** you need a C++20 compiler and `make`. Nothing else — no
package manager, no external SDK, and CMake is optional.

Two things the app does need from the *network*, rather than the machine:

- **A firewall allowance** if the NMOS node API is to be reachable. It binds a
  real interface on port 3210 by default, and a registry or controller that
  cannot reach it will list the sender but fail to route it.
- **mDNS on the local segment** for registry autodiscovery. Plenty of networks
  do not carry it between subnets, which is what the manual registry host and
  port override is for.

## Status

**Validated end to end against a real NMOS system**: a captured ST 2022-7 pair
replayed from disk, registered with a live registry, listed in NMOS Explorer,
routed by a controller to a hardware ST 2022-6 receiver, and decoded.

| Component | State |
|-----------|-------|
| Linux build and replay | ✅ Proven — 1080i25 at 100.0% of target packet rate, registered with a live registry, taken by a controller onto a hardware receiver bank and decoded |
| pcap ingest, format detection, marker-bit frame cutting, raster validation | ✅ Proven on 1080i25 and 625i25 captures |
| ST 2022-7 two-leg merge | ✅ Proven — recovers datagrams missing from one leg |
| Streaming ring buffer at line rate | ✅ Proven — 129 fps merged against 25 fps needed |
| Loop, fresh RTP/HBRMT, timecode rewrite, fault injection | ✅ Carried over from the earlier replay engine, unchanged |
| IS-04 registration, heartbeat, Node API | ✅ Proven against a live registry |
| IS-05 connection API, activation, destination change | ✅ Proven — routed by a controller, and a live destination change confirmed onto the wire |
| SDP manifest, incl. `a=group:DUP` for the -7 pair | ✅ Proven — accepted by a hardware receiver |
| BCP-002-01 group hint | ⚠️ Published and distinct per instance, read back from the Node API; not yet seen grouped by a controller |
| mDNS registry discovery | ✅ Proven — found and registered with a live registry over mDNS. `replay_cli --discover` checks your own segment |
| Peer-to-peer advertisement | ⚠️ Advertised and unique per instance; not exercised with a controller and no registry present |
| Two or more instances on one machine | ✅ Proven — distinct ports, UUIDs, labels and settings files, both registered at once |
| Scheduled IS-05 activation | ❌ Returns 501; only `activate_immediate` |
| Long-run registry garbage-collection recovery | ⚠️ 404-triggered re-registration written, not yet exercised over hours |

## Quick start

### Windows

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
.\build\bin\pcap_replay.exe
```

Pick a red capture, optionally a blue one, choose the multicast groups and the
NIC for each path, and press Start.

### Linux

```bash
make -j                        # or: cmake -S . -B build && cmake --build build
./build/bin/replay_cli --interfaces

./build/bin/replay_cli red.pcap blue.pcap \
    --group 239.2.2.2 --port 40000 --iface ens18 \
    --nmos --registry 10.0.0.5:3210
```

`--iface` takes an interface name or an address, and is worth giving: without it
multicast leaves by the default route, which on a machine with Docker installed
is very often a bridge rather than the wire. `--interfaces` lists them in the
order the GUI's dropdown uses — physical before virtual, fastest first — so
the top entry is nearly always the right one.

`replay_cli --help` lists everything the dialog offers: the per-path NIC and
group, TTL, fault injection, the NMOS configuration, and the status panel.

## Linux

The Linux build is the same engines with the dialog removed, not a rewrite. Every
file in `common/` and `nmos/` is shared; what differs is confined to the four
things the two operating systems genuinely disagree about — sockets, timing,
interface enumeration and DNS-SD — and `common/include/pcapreplay/platform.h`
is where the first of those is stated once.

### DNS-SD without a daemon

Windows has `DnsServiceBrowse`/`DnsServiceRegister` in `dnsapi.dll`. Linux has no
equivalent in libc, and the usual answer — link `libavahi-client` — costs the
property that makes this thing deployable: it adds a build dependency, a runtime
`.so`, and a requirement that `avahi-daemon` and D-Bus are both alive wherever it
runs. In a container that is not true without extra work, and a node that will
not start in a container is a node that will not start.

So `nmos/src/mdns_posix.cpp` speaks multicast DNS itself, from RFC 6762 and
RFC 6763: PTR queries with the exponential back-off section 5.2 asks for, SRV,
TXT and A follow-ups for anything a responder did not volunteer, and a responder
of its own that announces twice at startup (section 8.3) and sends a TTL 0
goodbye at shutdown (section 10.1), so a controller drops the node when it goes
rather than listing a sender that is not there.

**It coexists with `avahi-daemon` rather than competing with it.** The socket
takes `SO_REUSEADDR` and `SO_REUSEPORT` on 5353, and the kernel delivers each
multicast datagram to every socket joined to the group, so both processes see all
the traffic. The A record is published under `pcap-replay-<host>-<port>.local`
rather than `<host>.local`, because Avahi is already authoritative for the
latter and publishing a second answer for a name someone else owns is a conflict
— not a fight worth having for a record that exists only to point an SRV
somewhere. If 5353 cannot be shared at all, browsing falls back to a private port
and the unicast-response bit, which still finds registries; advertising cannot,
and says so rather than failing silently.

Verified against Avahi as an independent implementation: `avahi-browse -r
_nmos-node._tcp` resolves the instance, host, address, port and all nine TXT
records, and the entry disappears from Avahi's cache when the process is stopped.

What is deliberately not implemented: probing and conflict resolution (sections
8.1 and 9), and known-answer suppression. Every name published here already
carries the host name and the node port, which is the same thing that makes the
NMOS resource UUIDs unique; the suppressions are politeness optimisations for a
busy link, and one service instance and a query a minute is not what they exist
to protect against.

### Pacing

The structure is unchanged — absolute scheduling against a monotonic clock,
never incremental, coarse waits sleeping and the last few microseconds spinning.
`CLOCK_MONOTONIC` replaces `QueryPerformanceCounter` and is a vDSO read of the
TSC with no syscall, which matters on a path read tens of thousands of times a
second.

Linux sleeps far more accurately than Windows does: `clock_nanosleep` against an
absolute deadline lands within tens of microseconds, against Windows' 1—15 ms.
The spin threshold is therefore an order of magnitude tighter (150 us against
1.5 ms), so more packets are placed by sleeping to them and fewer by burning CPU.

Measured on 1080i25: **134,925 packets/sec sustained at 100.0% of target**, 25.00
frames/sec, zero repeated frames over a 280-second run.

`SCHED_FIFO` is the equivalent of `THREAD_PRIORITY_TIME_CRITICAL` and needs
`CAP_SYS_NICE`, which this tool does not demand. Unprivileged replay works and is
what the numbers above were measured with; it is simply more exposed to what else
the machine is doing. To grant it without running as root:

```bash
sudo setcap cap_sys_nice=eip ./build/bin/replay_cli
```

### Segmentation offload

Windows spells it `UDP_SEND_MSG_SIZE`, Linux spells it `UDP_SEGMENT` (generic
segmentation offload, kernel 4.18+). Both are set once on the socket, so one
`sendto()` hands the stack a buffer of many fixed-size datagrams and it splits
them — which is what makes ST 2022-6 packet rates reachable from a single
thread. Either can refuse, so the result is probed and `sendMany()` falls back to
a loop of `send()`.

Note that `tcpdump` on the sending host shows the *pre-segmentation* aggregate
— 64400-byte datagrams rather than 1400 — for the same reason it shows TSO
aggregates for TCP. A receiver sees 1400 bytes. Capture on the receiving side, or
on a tap, if that distinction matters.

One Linux-specific wrinkle is reported rather than hidden: `SO_SNDBUF` is clamped
to `net.core.wmem_max` without an error, and the stock 212 kB is a fifth of what
is asked for here. The granted size is read back and, if short, said out loud
— a silent clamp shows up later as spacing jitter that gets blamed on the
application.

### Choosing the interface

The single most common way to get nothing on the wire is to send out of the wrong
NIC, and on Linux the answer is less obvious than on Windows: a machine with
Docker installed has `docker0` and a bridge per compose network, all up, all
multicast-capable, and several of them reporting a link speed the real NIC does
not. `--interfaces` lists them physical-before-virtual and fastest-first, marking
bridges and tunnels as virtual, so sorting on speed alone cannot put a bridge at
the top.

### Running it as a service

`SIGINT`, `SIGTERM` and `SIGHUP` all unwind cleanly: the node deregisters from the
registry with an IS-04 `DELETE` and the responder sends its mDNS goodbye before
the process exits. A replay that is killed without unwinding leaves a sender in
the registry that is not there, which is exactly the failure this tool exists to
help diagnose.

```ini
[Unit]
Description=ST 2022-6 replay
After=network-online.target

[Service]
ExecStart=/usr/local/bin/replay_cli /srv/captures/red.pcap /srv/captures/blue.pcap \
          --group 239.2.2.2 --port 40000 --iface ens18 \
          --nmos --registry 10.0.0.5:3210 --quiet
AmbientCapabilities=CAP_SYS_NICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`--idle` registers the sender but does not transmit until a controller activates
it over IS-05, which is usually what you want from a service.

### Reading the capture off disk

The disk requirement is the same on both platforms and is the thing most likely
to bite: 1080i25 needs ~190 MB/s per leg, so ~380 MB/s for a `-7` pair. Measure
before blaming anything else:

```bash
./build/bin/replay_cli red.pcap blue.pcap --ingest 30
```

On a machine whose disk cannot keep up, the transmitter repeats the current frame
rather than stalling — a gap on the wire reads to a receiver as a fault, whereas
a repeated frame keeps the packet rate and the RTP sequence continuous — and the
repeat count is shown so it stays visible rather than silent. Measured 292 fps
single-leg with the capture in page cache, against the 25 needed.

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
| Discovery | mDNS browse for **both** `_nmos-register._tcp` and `_nmos-registration._tcp`, with a manual host/port override |
| Peer-to-peer | Advertises `_nmos-node._tcp`, so a controller can find the node with no registry present |
| BCP-002-01 | `urn:x-nmos:tag:grouphint/v1.0` on the sender, e.g. `PCAP Replay THEBEAST-3210:2022-6` |

ST 2022-6 carries a whole SDI signal, so it is modelled as a **mux**: the source
and flow are `urn:x-nmos:format:mux`, the flow's `media_type` is
`video/SMPTE2022-6`, and the sender's transport is
`urn:x-nmos:transport:rtp.mcast`. This was checked against a dump of a
third-party broadcast ST 2022-6 sender.

Resource UUIDs are **deterministic** (UUID v5 over the machine name and the
resource role), so they survive a restart and a controller's existing route
still points at something that exists.

### More than one instance on a machine

Nothing in IS-04 requires the node API to be on 3210 — it is a convention, and
the node's own `href` and its DNS-SD advertisement both carry whatever was
actually bound. So a second instance **steps to the next free port** rather than
refusing to start, and says so in the status panel. The loopback stats port does
the same, so the second instance keeps a scriptable surface too.

A second instance also needs its own identity, or both copies register the same
UUIDs and fight over them in the registry. The node port therefore joins the UUID
seed — but **only when it is not 3210**, so an instance on the default port keeps
exactly the IDs it had before and an existing route is not orphaned by upgrading.

| | Instance 1 | Instance 2 |
|---|---|---|
| Node API | `:3210` | `:3211` |
| Stats | `:49610` | `:49611` |
| Settings | `replay.ini` | `replay-3211.ini` |
| Sender UUID | unchanged from before | its own |
| Label | `PCAP Replay EDIT-1:3210 - 1080i25` | `PCAP Replay EDIT-1:3211 - 625i25` |
| Group hint | `PCAP Replay EDIT-1-3210:2022-6` | `PCAP Replay EDIT-1-3211:2022-6` |

All three come from one slot number, so they cannot drift apart. A slot is claimed
only when *both* its ports are free — keying on the node port alone would drop two
instances into the same settings file whenever the first had NMOS switched off and
so never bound one.

Settings **write** to the instance's own file and **read** through to the first
instance's when it has no answer of its own. A second instance that opened blank —
no capture, no NIC, NMOS off — would not be a useful second instance; inheriting
and then diverging on whatever you change is what makes starting one worthwhile.
The node port is the exception and is never inherited, since it is the thing that
makes the instance distinct.

Labels carry the host and port **and** the loaded format, because that is what
someone is choosing between in a controller. The host matters as much as the
port: every machine hands out 3210 first, so two hosts each running one instance
would otherwise present two senders with the same name. The UUIDs were never at
risk there — the machine name has always been in the seed — but a registry full
of identically named senders is its own kind of unusable. The format is deliberately *not* in the UUID
seed: a UUID is an identity and has to outlive the thing it identifies changing,
so folding the format in would mint a whole new node, device, source, flow and
sender every time a different capture was loaded, and break every route a
controller had made. Labels may change over a resource's life; identities may
not.

### The group hint

The sender carries a BCP-002-01 group hint,
`urn:x-nmos:tag:grouphint/v1.0`, in the form `{group name}:{role in group}`:

```
PCAP Replay THEBEAST-3210:2022-6
```

Controllers use it to gather everything belonging to one physical thing under
one heading instead of listing loose senders in whatever order the registry
returns them.

The group names the *instance* — label, host and node port — and deliberately
stops there. Host and port are in it for the same reason they are in the label:
the port separates two copies on one machine, the host separates copies on
different machines, and every machine hands out 3210 first, so a bare
`PCAP Replay-3210` would fold two hosts into one group and claim a relationship
that does not exist. The colon is the field delimiter, so the label's `host:port`
is written `host-port` here, and a colon typed into the Label box is folded the
same way rather than being read as an early end to the group name.

What is *not* in it: the loaded format, which the label does carry. Opening a
different capture would otherwise move the sender into a brand new group each
time — precisely the churn grouping exists to prevent. Nor does the role follow
`-6`/`-7`: an ST 2022-7 pair is one sender with a redundant path, not two
senders, so the role stays `2022-6` and a controller's grouping survives the
switch.

The panel prints the hint next to the sender UUID, so it can be read off the
screen rather than fetched out of the Node API.

### Finding the registry

Both DNS-SD service types are browsed, because which one a registry advertises
depends on the API versions it serves: IS-04 named the Registration API
`_nmos-registration._tcp` up to v1.2, and added the shorter `_nmos-register._tcp`
at v1.3 because the first is 18 characters against the 16 RFC 6763 §7.2 allows.
Browsing only the v1.3 name means a registry that is plainly on the network is
never seen.

To check a segment before blaming anything else:

```powershell
.\build\bin\replay_cli.exe --discover 10
```

That browses both types, prints every registry with its address, priority and
advertised `api_ver`, and says which one the node would register with — or why
none of them will do. It needs no capture file.

The status panel then shows whether registration actually happened and against
which registry, so "listed in the controller" and "registered" cannot be confused
for each other.

### Changing the destination from a controller

The transmit sockets are bound to their group when they are opened, so moving the
sender means restarting the engine. Three things follow from that, and all three
are enforced:

- The restart is **confirmed, not assumed**. If the engine does not come back up
  on the new group, IS-05 answers `500` with the reason rather than `200`. A
  controller treats `200` as "the sender has moved".
- What is reported is **what is on the wire**, read back from the running engine
  rather than from what the GUI last asked for. The Node API, the IS-05 `active`
  endpoint and the SDP therefore cannot advertise a group nothing is being sent
  to.
- The GUI fields follow an IS-05 change. They are what every start path builds
  its configuration from, so leaving them stale meant the next fault checkbox or
  Start press silently reinstated the old group and undid the routing.

`master_enable` is kept in step with the engine for the same reason. IS-05 makes
a PATCH a partial update of `staged`, so anything the body omits keeps its staged
value — which is correct, and only works if `staged` tracks reality. Here reality
can move without IS-05 touching it, because the GUI can start and stop the replay
itself.

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
measurement. On Linux it is the whole product; `--help` lists every option.

```powershell
# is an NMOS registry discoverable from this machine? (needs no capture)
.\build\bin\replay_cli.exe --discover 10

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

Port 49610 is chosen because it is not normally in use, so the status endpoint
is unlikely to collide with anything else on the machine.

## Supported formats

1080i25/29.97/30 · 1080p25/29.97/30/50/59.94/60 · 1080PsF25 · 720p50/59.94/60 ·
625i25 · 525i29.97, all 4:2:2 10-bit.

Captures must be **classic pcap**, not pcapng. Ethernet, raw IPv4, Linux SLL and
NULL/loopback link types are all handled.

## Layout

| Path | What is in it |
|------|---------------|
| `common/` | SDI format tables, 10-bit packing, CRC, HBRMT/RTP, multicast, pacer, the pcap source and the replay engine |
| `common/include/pcapreplay/platform.h` | the whole of the Winsock/Berkeley sockets difference, stated once |
| `nmos/` | JSON, HTTP server and client, DNS-SD, and the IS-04/IS-05 node |
| `nmos/src/mdns_win.cpp` | DNS-SD on `dnsapi.dll` |
| `nmos/src/mdns_posix.cpp` | DNS-SD spoken directly over UDP 5353 |
| `app/` | the Win32 dialog. Not built on Linux |
| `tools/` | `replay_cli` — the whole product on Linux |

Files whose name ends `_win` or `_posix` are compiled on both platforms and are
empty on the one they are not for, so neither can rot unnoticed behind a
generator expression. Everything else is shared, with `#ifdef` only where the two
platforms genuinely disagree.

`common/` is the earlier `st2022_common` with the live-video half removed and
the namespace renamed to `pcapreplay`.

The NMOS layer is hand-rolled rather than sony/nmos-cpp, so the app stays a
single executable: nmos-cpp has no vcpkg port, its `cpprestsdk` and `websocketpp`
dependencies have both been **removed from vcpkg**, and its supported build path
is now Conan. `NmosBackend` in `nmos/include/pcapreplay/nmos/nmos_node.h` is the
seam — adding an nmos-cpp backend means another implementation of that
interface, not a rewrite of the app.

**No nmos-cpp code is used here.** Not a file, not a function, not a line. The
IS-04 and IS-05 implementations in `nmos/` were written from the AMWA
specifications, and nmos-cpp was consulted only as a reference for how those
specifications are read in practice — see the acknowledgement below.

## Acknowledgements

Thank you to the authors and maintainers of **[sony/nmos-cpp][nmos-cpp]**, the
reference open-source implementation of the AMWA NMOS specifications, released
under the **Apache License 2.0**.

nmos-cpp was used here as a *reference*, in the ordinary sense of reading a
well-regarded implementation to check an understanding of the specifications
against one that is known to interoperate. Two points in this codebase are the
better for it:

- that the Registration API is advertised as `_nmos-registration._tcp` for IS-04
  v1.0–v1.2 and `_nmos-register._tcp` for v1.3 and later, so both have to be
  browsed;
- that an IS-05 PATCH is a merge over `staged`, so a field the request omits
  keeps its staged value rather than being re-read from `active`.

Both are facts about IS-04 and IS-05 rather than about nmos-cpp's expression of
them. **No nmos-cpp source code has been copied, adapted or linked**, in whole or
in part, so no Apache 2.0 obligation attaches to this project — the thanks are
owed regardless.

[nmos-cpp]: https://github.com/sony/nmos-cpp

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
