// The NMOS node, driven through its own APIs on an ephemeral port with no
// registry present. This is the contract a controller actually reads: the IS-04
// resource chain, the IS-05 connection endpoints, and the SDP it hands to a
// receiver. All of it is served fresh from the query callback, so these also
// pin down that the node reports what the engine is doing rather than what it
// was last told.
#include "harness.h"

#include <memory>
#include <mutex>
#include <string>

#include "pcapreplay/nmos/http.h"
#include "pcapreplay/nmos/json.h"
#include "pcapreplay/nmos/nmos_node.h"

using namespace pcapreplay::nmos;

namespace {

struct Node {
    std::unique_ptr<NmosBackend> backend{createBuiltinBackend()};
    std::uint16_t port = 0;
    std::string nodeBase, connBase, senderId;

    mutable std::mutex m;
    SenderTransport want;
    std::string applyError;      // non-empty makes apply() reject

    Node() {
        want.active      = true;
        want.redundant   = false;
        want.sourceIpA   = "10.0.0.1";
        want.destIpA     = "239.1.1.1";
        want.destPortA   = 40000;
        want.interfaceNameA = "eth0";
        want.macA        = "02-00-5e-00-00-01";
        want.frameRateNum = 25;
        want.frameRateDen = 1;
        want.formatText  = "1080i25 (1080i50)  1920x1080  1.485 Gb/s";
    }

    bool start() { return startOn(0); }
    bool startOn(std::uint16_t fixedPort) {
        backend->setCallbacks(
            [this] { std::lock_guard<std::mutex> lk(m); return want; },
            [this](const SenderTransport& w, std::string& err) {
                std::lock_guard<std::mutex> lk(m);
                if (!applyError.empty()) { err = applyError; return false; }
                want = w;
                return true;
            });
        NmosConfig c;
        c.enabled  = true;
        c.label    = "TestNode";
        c.nodeIp   = "127.0.0.1";
        c.nodePort = fixedPort;               // 0 = ephemeral
        c.useMdns  = false;                   // no browse, no registry
        c.advertisePeerToPeer = false;
        if (!backend->start(c)) return false;
        const NmosStatus st = backend->status();
        port     = std::uint16_t(std::atoi(
                       st.nodeApiUrl.substr(st.nodeApiUrl.rfind(':') + 1).c_str()));
        senderId = st.senderId;
        nodeBase = "/x-nmos/node/v1.3";
        connBase = "/x-nmos/connection/v1.1";
        return port != 0 && !senderId.empty();
    }
    ~Node() { backend->stop(); }

    std::string why() const {
        const std::string e = backend->status().error;
        return e.empty() ? std::string("no reason given") : e;
    }

    HttpResult get(const std::string& t) const {
        return httpRequest("127.0.0.1", port, "GET", t, {}, "application/json", 3000);
    }
    HttpResult patch(const std::string& t, const std::string& body) const {
        return httpRequest("127.0.0.1", port, "PATCH", t, body, "application/json", 8000);
    }
    Json json(const std::string& t) const {
        std::string err;
        return Json::parse(get(t).body, err);
    }
};

}  // namespace

TEST(nmos_node, serves_the_is04_resource_chain) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());

    // Every resource a controller walks, and the links between them. A broken
    // link is how a sender ends up listed but unroutable.
    const Json self   = n.json(n.nodeBase + "/self");
    const Json sender = n.json(n.nodeBase + "/senders/" + n.senderId);
    CHECK(self.isObject());
    CHECK(sender.isObject());

    const std::string nodeId   = self.at("id").asString();
    const std::string deviceId = sender.at("device_id").asString();
    const std::string flowId   = sender.at("flow_id").asString();
    CHECK(!nodeId.empty());
    CHECK(!deviceId.empty());
    CHECK(!flowId.empty());

    const Json device = n.json(n.nodeBase + "/devices/" + deviceId);
    CHECK_EQ(device.at("node_id").asString(), nodeId);

    const Json flow = n.json(n.nodeBase + "/flows/" + flowId);
    const std::string sourceId = flow.at("source_id").asString();
    const Json source = n.json(n.nodeBase + "/sources/" + sourceId);
    CHECK_EQ(source.at("device_id").asString(), deviceId);

    // ST 2022-6 carries a whole SDI signal -- video, embedded audio and the
    // ancillary data together -- so it is a mux, not a video flow.
    CHECK_EQ(flow.at("format").asString(), std::string("urn:x-nmos:format:mux"));
    CHECK_EQ(source.at("format").asString(), std::string("urn:x-nmos:format:mux"));
    CHECK_EQ(flow.at("media_type").asString(), std::string("video/SMPTE2022-6"));
    CHECK_EQ(sender.at("transport").asString(),
             std::string("urn:x-nmos:transport:rtp.mcast"));
}

TEST(nmos_node, the_grain_rate_is_an_exact_rational) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const Json flow = n.json(n.nodeBase + "/flows/" +
        n.json(n.nodeBase + "/senders/" + n.senderId).at("flow_id").asString());
    CHECK_EQ(flow.at("grain_rate").at("numerator").asInt(), std::int64_t(25));
    CHECK_EQ(flow.at("grain_rate").at("denominator").asInt(), std::int64_t(1));
}

TEST(nmos_node, the_sender_carries_a_bcp_002_group_hint) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const Json sender = n.json(n.nodeBase + "/senders/" + n.senderId);
    const Json& tags = sender.at("tags");
    CHECK(tags.has("urn:x-nmos:tag:grouphint/v1.0"));
    const std::string hint =
        tags.at("urn:x-nmos:tag:grouphint/v1.0").elements()[0].asString();
    // "{group name}:{role in group}". The role names the essence, not the leg
    // count, so toggling -7 must not rename the sender out of its group.
    CHECK(hint.rfind(":2022-6") == hint.size() - 7);
    CHECK(hint.find("TestNode") == 0);
}

TEST(nmos_node, the_label_carries_the_loaded_format) {
    // What someone is choosing between in a controller is the format, so it is
    // in the label -- and deliberately not in the UUID seed, because a UUID has
    // to outlive the thing it identifies changing.
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const Json sender = n.json(n.nodeBase + "/senders/" + n.senderId);
    CHECK(sender.at("label").asString().find("1080i25") != std::string::npos);
}

TEST(nmos_node, ids_are_stable_across_a_restart) {
    // If they were not, every restart would look to the registry like a new
    // node and every route a controller had made would dangle.
    //
    // A fixed port, deliberately: the node port joins the UUID seed whenever it
    // is not the default 3210, so that two instances on one machine do not
    // register the same IDs and fight over them. An ephemeral port therefore
    // mints new IDs every time, which is correct and is why this cannot be
    // tested on one.
    const std::uint16_t port = firstFreePort("127.0.0.1", 39210, 20);
    if (port == 0) SKIP("no free port to pin the identity to");

    std::string first;
    for (int pass = 0; pass < 2; ++pass) {
        Node n;
        if (!n.startOn(port)) SKIP(("cannot bind the pinned port: " + n.why()).c_str());
        if (pass == 0) first = n.senderId;
        else           CHECK_EQ(n.senderId, first);
    }
}

TEST(nmos_node, two_instances_on_different_ports_get_different_ids) {
    // The other half of the same rule: two copies on one machine must not
    // register the same UUIDs.
    const std::uint16_t a = firstFreePort("127.0.0.1", 39240, 10);
    const std::uint16_t b = firstFreePort("127.0.0.1", std::uint16_t(a + 1), 10);
    if (a == 0 || b == 0 || a == b) SKIP("no two free ports here");

    Node na, nb;
    if (!na.startOn(a) || !nb.startOn(b)) SKIP(("cannot bind the pinned ports: " + na.why()).c_str());
    CHECK_NE(na.senderId, nb.senderId);
}

TEST(nmos_node, is05_reports_constraints_staged_and_active) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const std::string base = n.connBase + "/single/senders/" + n.senderId;

    const Json constraints = n.json(base + "/constraints");
    CHECK(constraints.isArray());
    CHECK_EQ(constraints.size(), std::size_t(1));    // one leg, not redundant

    const Json active = n.json(base + "/active");
    CHECK_EQ(active.at("master_enable").asBool(), true);
    const Json& tp = active.at("transport_params").elements()[0];
    CHECK_EQ(tp.at("destination_ip").asString(), std::string("239.1.1.1"));
    CHECK_EQ(tp.at("destination_port").asInt(), std::int64_t(40000));

    CHECK(n.json(base + "/staged").isObject());
    CHECK_EQ(n.get(n.connBase + "/single/senders/" + n.senderId + "/transporttype")
                 .status, 200);
}

TEST(nmos_node, an_is05_patch_moves_the_sender) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const std::string base = n.connBase + "/single/senders/" + n.senderId;

    const auto r = n.patch(base + "/staged",
        R"({"transport_params":[{"destination_ip":"239.9.9.9","destination_port":40100}],)"
        R"("activation":{"mode":"activate_immediate"}})");
    CHECK_EQ(r.status, 200);

    // What is reported is what the callback was actually given, read back from
    // the active endpoint -- not what the request asked for.
    //
    // The document is held by value: binding a reference straight into
    // n.json(...) would reference a temporary that dies at the end of the
    // statement.
    const Json active = n.json(base + "/active");
    const Json& tp = active.at("transport_params").elements()[0];
    CHECK_EQ(tp.at("destination_ip").asString(), std::string("239.9.9.9"));
    CHECK_EQ(tp.at("destination_port").asInt(), std::int64_t(40100));
}

TEST(nmos_node, a_patch_is_a_merge_over_staged) {
    // IS-05 makes a PATCH a partial update: a field the body omits keeps its
    // staged value rather than being re-read from active.
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const std::string base = n.connBase + "/single/senders/" + n.senderId;

    CHECK_EQ(n.patch(base + "/staged",
        R"({"transport_params":[{"destination_port":40200}],)"
        R"("activation":{"mode":"activate_immediate"}})").status, 200);

    const Json active = n.json(base + "/active");
    const Json& tp = active.at("transport_params").elements()[0];
    CHECK_EQ(tp.at("destination_port").asInt(), std::int64_t(40200));
    CHECK_EQ(tp.at("destination_ip").asString(), std::string("239.1.1.1"));
}

TEST(nmos_node, a_rejected_activation_answers_500_not_200) {
    // A controller reads 200 as "the sender has moved". If the engine did not
    // come back up on the new group, 200 is a lie it will not find out about.
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    { std::lock_guard<std::mutex> lk(n.m); n.applyError = "the engine did not start"; }

    const auto r = n.patch(n.connBase + "/single/senders/" + n.senderId + "/staged",
        R"({"transport_params":[{"destination_ip":"239.8.8.8"}],)"
        R"("activation":{"mode":"activate_immediate"}})");
    CHECK_EQ(r.status, 500);
    CHECK(r.body.find("the engine did not start") != std::string::npos);
}

TEST(nmos_node, scheduled_activation_is_refused_explicitly) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const auto r = n.patch(n.connBase + "/single/senders/" + n.senderId + "/staged",
        R"({"activation":{"mode":"activate_scheduled_absolute",)"
        R"("requested_time":"1700000000:0"}})");
    // 501, rather than accepting it and never acting.
    CHECK_EQ(r.status, 501);
}

TEST(nmos_node, the_sdp_describes_a_single_leg_sender) {
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    const std::string sdp =
        n.get(n.connBase + "/single/senders/" + n.senderId + "/transportfile").body;

    CHECK(sdp.rfind("v=0", 0) == 0);
    CHECK(sdp.find("m=video 40000 RTP/AVP 98") != std::string::npos);
    CHECK(sdp.find("c=IN IP4 239.1.1.1/") != std::string::npos);
    CHECK(sdp.find("a=rtpmap:98 SMPTE2022-6/27000000") != std::string::npos);
    CHECK(sdp.find("a=source-filter: incl IN IP4 239.1.1.1 10.0.0.1") !=
          std::string::npos);
    // This machine is not PTP locked, so claiming a traceable reference would
    // make a receiver's timing decisions wrong rather than merely conservative.
    CHECK(sdp.find("a=ts-refclk:localmac=02-00-5e-00-00-01") != std::string::npos);
    CHECK(sdp.find("ptp=IEEE1588") == std::string::npos);
    // One leg, so no redundancy grouping.
    CHECK(sdp.find("a=group:DUP") == std::string::npos);
}

TEST(nmos_node, a_redundant_pair_is_two_grouped_m_lines) {
    // RFC 7104: how a receiver is told the two legs are copies of each other
    // rather than two different essences.
    Node n;
    n.want.redundant = true;
    n.want.destIpB   = "239.2.2.2";
    n.want.destPortB = 40000;
    n.want.sourceIpB = "10.0.0.2";
    n.want.macB      = "02-00-5e-00-00-02";
    n.want.interfaceNameB = "eth1";
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());

    const std::string sdp =
        n.get(n.connBase + "/single/senders/" + n.senderId + "/transportfile").body;
    CHECK(sdp.find("a=group:DUP") != std::string::npos);
    CHECK(sdp.find("a=mid:primary") != std::string::npos);
    CHECK(sdp.find("a=mid:secondary") != std::string::npos);
    CHECK(sdp.find("c=IN IP4 239.1.1.1/") != std::string::npos);
    CHECK(sdp.find("c=IN IP4 239.2.2.2/") != std::string::npos);

    // And IS-05 must offer two legs to configure, not one.
    CHECK_EQ(n.json(n.connBase + "/single/senders/" + n.senderId + "/constraints")
                 .size(), std::size_t(2));
}

TEST(nmos_node, bulk_and_base_endpoints_are_reachable) {
    // Controllers probe their way down the tree; a missing intermediate listing
    // stops the walk before it reaches the sender.
    Node n;
    if (!n.start()) SKIP(("cannot start a node here: " + n.why()).c_str());
    for (const std::string& path : {std::string("/"), std::string("/x-nmos"),
                                    n.nodeBase, n.connBase,
                                    n.connBase + "/single",
                                    n.connBase + "/single/senders",
                                    n.nodeBase + "/senders",
                                    n.nodeBase + "/receivers"}) {
        CHECK_EQ(n.get(path).status, 200);
    }
    // This app only sends.
    CHECK_EQ(n.json(n.nodeBase + "/receivers").size(), std::size_t(0));
}
