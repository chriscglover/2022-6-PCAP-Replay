// A hand-rolled JSON codec that an NMOS registry validates against a schema.
// Anything it emits wrong comes back as an opaque 400.
#include "harness.h"

#include "pcapreplay/nmos/json.h"

using namespace pcapreplay::nmos;

TEST(json, round_trips_through_dump_and_parse) {
    Json o = Json::object();
    o["label"]   = Json("PCAP Replay");
    o["port"]    = Json(std::int64_t(3210));
    o["enabled"] = Json(true);
    o["absent"]  = Json(nullptr);
    o["rate"]    = Json(25.0);
    Json a = Json::array();
    a.push(Json("one"));
    a.push(Json(std::int64_t(2)));
    o["list"] = a;

    std::string err;
    const Json back = Json::parse(o.dump(), err);
    CHECK(err.empty());
    CHECK(back.isObject());
    CHECK_EQ(back.at("label").asString(), std::string("PCAP Replay"));
    CHECK_EQ(back.at("port").asInt(), std::int64_t(3210));
    CHECK_EQ(back.at("enabled").asBool(), true);
    CHECK(back.at("absent").isNull());
    CHECK(back.at("list").isArray());
    CHECK_EQ(back.at("list").size(), std::size_t(2));
    CHECK_EQ(back.at("list").elements()[0].asString(), std::string("one"));
}

TEST(json, escapes_what_must_be_escaped) {
    const std::string nasty = "quote\" back\\slash\nnewline\ttab\rcr";
    Json o = Json::object();
    o["s"] = Json(nasty);

    std::string err;
    const Json back = Json::parse(o.dump(), err);
    CHECK(err.empty());
    CHECK_EQ(back.at("s").asString(), nasty);

    // Control characters have to become \u escapes, not raw bytes.
    const std::string esc = jsonEscape(std::string("\x01\x1f"));
    CHECK(esc.find("\\u00") != std::string::npos);
}

TEST(json, unicode_survives_a_round_trip) {
    // NMOS labels are free text and a controller may well contain non-ASCII.
    const std::string s = "Studio \xc3\x85 \xe2\x80\x94 caf\xc3\xa9";
    Json o = Json::object();
    o["label"] = Json(s);
    std::string err;
    CHECK_EQ(Json::parse(o.dump(), err).at("label").asString(), s);
    CHECK(err.empty());
}

TEST(json, parses_escapes_it_did_not_write) {
    // A controller's PATCH body is not written by us.
    std::string err;
    const Json j = Json::parse(R"({"a":"Aé\/x","b":"\b\f"})", err);
    CHECK(err.empty());
    CHECK_EQ(j.at("a").asString(), std::string("A\xc3\xa9/x"));
    CHECK_EQ(j.at("b").asString(), std::string("\b\f"));
}

TEST(json, numbers_keep_their_kind) {
    std::string err;
    const Json j = Json::parse(R"({"i":42,"neg":-7,"real":1.5,"exp":2.5e3,"big":900900})", err);
    CHECK(err.empty());
    CHECK_EQ(j.at("i").asInt(), std::int64_t(42));
    CHECK_EQ(j.at("neg").asInt(), std::int64_t(-7));
    CHECK_EQ(j.at("real").asReal(), 1.5);
    CHECK_EQ(j.at("exp").asReal(), 2500.0);
    CHECK_EQ(j.at("big").asInt(), std::int64_t(900900));
    CHECK(j.at("i").isNumber());
    CHECK(!j.at("i").isString());
}

TEST(json, rejects_malformed_input_with_a_reason) {
    for (const char* bad : {"{", "{\"a\"}", "[1,]", "{\"a\":}", "tru",
                            "\"unterminated", "{\"a\":1,}"}) {
        std::string err;
        Json::parse(bad, err);
        CHECK(!err.empty());
    }
}

TEST(json, missing_keys_do_not_insert_or_throw) {
    Json o = Json::object();
    o["present"] = Json(1);
    CHECK(!o.has("absent"));
    CHECK(o.at("absent").isNull());
    CHECK(!o.has("absent"));            // at() must not have inserted it
    CHECK_EQ(o.at("absent").asString("fallback"), std::string("fallback"));
    CHECK_EQ(o.at("absent").asInt(99), std::int64_t(99));
}

TEST(json, empty_containers_dump_as_themselves) {
    std::string err;
    CHECK_EQ(Json::object().dump(), std::string("{}"));
    CHECK_EQ(Json::array().dump(), std::string("[]"));
    CHECK(Json::parse("{}", err).isObject());
    CHECK(Json::parse("[]", err).isArray());
    CHECK(err.empty());
}

TEST(json, nesting_survives) {
    // IS-05 bodies nest transport_params inside an array inside an object.
    std::string err;
    const Json j = Json::parse(
        R"({"transport_params":[{"destination_ip":"239.1.1.1","destination_port":40000}],
            "activation":{"mode":"activate_immediate"}})", err);
    CHECK(err.empty());
    const Json& tp0 = j.at("transport_params").elements()[0];
    CHECK_EQ(tp0.at("destination_ip").asString(), std::string("239.1.1.1"));
    CHECK_EQ(tp0.at("destination_port").asInt(), std::int64_t(40000));
    CHECK_EQ(j.at("activation").at("mode").asString(),
             std::string("activate_immediate"));
}
