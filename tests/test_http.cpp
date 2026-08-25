// The HTTP server an NMOS controller talks to, exercised over loopback rather
// than by inspection. Routing, the verbs IS-05 needs, and the CORS headers
// without which the browser-based controllers cannot see the node at all.
#include "harness.h"

#include <atomic>
#include <thread>
#include <vector>

#include "pcapreplay/nmos/http.h"

using namespace pcapreplay::nmos;

namespace {

// A server on an ephemeral port, so tests never collide with a running node or
// with each other.
struct Server {
    HttpServer s;
    std::uint16_t port = 0;
    bool start() {
        if (!s.start("127.0.0.1", 0)) return false;
        port = s.port();
        return port != 0;
    }
    std::string why() const {
        return s.error().empty() ? std::string("no reason given") : s.error();
    }
    HttpResult get(const std::string& target) {
        return httpRequest("127.0.0.1", port, "GET", target, {}, "application/json", 3000);
    }
    HttpResult send(const std::string& method, const std::string& target,
                    const std::string& body = {}) {
        return httpRequest("127.0.0.1", port, method, target, body,
                           "application/json", 3000);
    }
};

}  // namespace

TEST(http, url_decoding_handles_escapes_and_plus) {
    CHECK_EQ(urlDecode("plain"), std::string("plain"));
    CHECK_EQ(urlDecode("a%20b"), std::string("a b"));
    CHECK_EQ(urlDecode("a+b"), std::string("a b"));
    CHECK_EQ(urlDecode("%2Fx%2Fy"), std::string("/x/y"));
    CHECK_EQ(urlDecode("caf%C3%A9"), std::string("caf\xc3\xa9"));
    // A stray percent must pass through rather than eat the next two bytes.
    CHECK_EQ(urlDecode("100%"), std::string("100%"));
    CHECK_EQ(urlDecode("%zz"), std::string("%zz"));
}

TEST(http, serves_a_route_and_reports_the_bound_port) {
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/hello", [](const HttpRequest&, HttpResponse& res) {
        res.text("world");
    });
    const auto r = sv.get("/hello");
    CHECK(r.ok);
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, std::string("world"));
    sv.s.stop();
}

TEST(http, pattern_segments_capture_into_params) {
    // This is how IS-05 addresses a sender: .../single/senders/:id/staged
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/x-nmos/connection/v1.1/single/senders/:id/staged",
               [](const HttpRequest& req, HttpResponse& res) {
                   res.text(req.params.at("id"));
               });
    const auto r = sv.get("/x-nmos/connection/v1.1/single/senders/abc-123/staged");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, std::string("abc-123"));
    sv.s.stop();
}

TEST(http, cors_headers_are_on_every_response) {
    // The reference NMOS controllers are browser applications. A node without
    // these is simply invisible to them, and the failure looks like the node
    // not being there at all.
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/thing", [](const HttpRequest&, HttpResponse& res) {
        res.json("{}");
    });

    const auto ok = sv.get("/thing");
    CHECK_EQ(ok.headers.count("access-control-allow-origin"), std::size_t(1));
    CHECK_EQ(ok.headers.at("access-control-allow-origin"), std::string("*"));

    // Including on a 404, which is what a controller probing an endpoint gets.
    const auto missing = sv.get("/nope");
    CHECK_EQ(missing.status, 404);
    CHECK_EQ(missing.headers.count("access-control-allow-origin"), std::size_t(1));

    // And on the preflight, which the browser sends before a PATCH.
    const auto pre = sv.send("OPTIONS", "/thing");
    CHECK(pre.status == 200 || pre.status == 204);
    CHECK_EQ(pre.headers.count("access-control-allow-methods"), std::size_t(1));
    CHECK(pre.headers.at("access-control-allow-methods").find("PATCH") !=
          std::string::npos);
    sv.s.stop();
}

TEST(http, the_right_status_for_the_wrong_method) {
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/only-get", [](const HttpRequest&, HttpResponse& res) {
        res.text("yes");
    });
    // A path that exists but not for this verb is 405, not 404 -- a controller
    // uses the difference to tell "no such resource" from "not supported here".
    CHECK_EQ(sv.send("PATCH", "/only-get", "{}").status, 405);
    CHECK_EQ(sv.get("/no-such-path").status, 404);
    sv.s.stop();
}

TEST(http, head_returns_the_headers_without_the_body) {
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/thing", [](const HttpRequest&, HttpResponse& res) {
        res.text("some body text");
    });
    const auto r = sv.send("HEAD", "/thing");
    CHECK_EQ(r.status, 200);
    CHECK(r.body.empty());
    sv.s.stop();
}

TEST(http, a_patch_body_arrives_intact) {
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    std::string seen;
    sv.s.route("PATCH", "/staged", [&](const HttpRequest& req, HttpResponse& res) {
        seen = req.body;
        res.json(R"({"ok":true})");
    });
    const std::string body =
        R"({"transport_params":[{"destination_ip":"239.1.1.1"}],)"
        R"("activation":{"mode":"activate_immediate"}})";
    const auto r = sv.send("PATCH", "/staged", body);
    CHECK_EQ(r.status, 200);
    CHECK_EQ(seen, body);
    sv.s.stop();
}

TEST(http, a_query_string_is_split_from_the_path) {
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/senders", [](const HttpRequest& req, HttpResponse& res) {
        res.text(req.path + "|" + req.query);
    });
    const auto r = sv.get("/senders?label=x&pri=1");
    CHECK_EQ(r.body, std::string("/senders|label=x&pri=1"));
    sv.s.stop();
}

TEST(http, wildcard_routes_match_deeper_paths) {
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/base/*", [](const HttpRequest&, HttpResponse& res) {
        res.text("matched");
    });
    CHECK_EQ(sv.get("/base/one/two/three").status, 200);
    sv.s.stop();
}

TEST(http, concurrent_requests_are_all_served) {
    // Four worker threads sit behind one accept loop; a registry heartbeat and
    // a controller poll do arrive together.
    Server sv;
    if (!sv.start()) SKIP(("cannot bind a loopback port here: " + sv.why()).c_str());
    sv.s.route("GET", "/ping", [](const HttpRequest&, HttpResponse& res) {
        res.text("pong");
    });
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i)
        threads.emplace_back([&] {
            for (int k = 0; k < 4; ++k)
                if (sv.get("/ping").body == "pong") ++ok;
        });
    for (auto& t : threads) t.join();
    CHECK_EQ(ok.load(), 32);
    CHECK(sv.s.requestsServed() >= 32);
    sv.s.stop();
}

TEST(http, a_client_reports_an_unreachable_peer_rather_than_hanging) {
    // Port 1 on loopback refuses immediately; the point is that it comes back
    // as a failure rather than sitting in the stack's own retry.
    const auto r = httpRequest("127.0.0.1", 1, "GET", "/", {}, "application/json", 1000);
    CHECK(!r.success());
    CHECK(!r.error.empty());
}

TEST(http, free_port_probing_finds_something_usable) {
    const std::uint16_t p = firstFreePort("127.0.0.1", 49700, 20);
    // Zero means the whole span was taken -- or, on a locked-down runner, that
    // a loopback listener cannot be bound at all. Either is about the machine
    // rather than about the probe.
    if (p == 0) SKIP("no bindable loopback port in 49700-49719 here");
    CHECK(p >= 49700);
    CHECK(p < 49720);
}
