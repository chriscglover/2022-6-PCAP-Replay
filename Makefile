# Linux build. `make` and a C++20 compiler, nothing else.
#
# CMakeLists.txt builds this too and is what the Windows side uses, but a plain
# makefile is worth having here: it is the difference between "install cmake
# first" and "it builds", and on a machine whose job is to put video on the wire
# the second is the right answer. The two produce the same binary.
#
#   make            release build -> build/bin/replay_cli
#   make -j         ... in parallel
#   make test       build and run the test suite
#   make debug      -O0 -g, with the sanitisers off
#   make asan       address and UB sanitisers, for chasing a crash
#   make install    to $(PREFIX)/bin, default /usr/local
#   make clean

CXX      ?= g++
PREFIX   ?= /usr/local
BUILD    ?= build

CXXSTD   := -std=c++20
WARN     := -Wall -Wextra
INCLUDES := -Icommon/include -Inmos/include -Iapp

CXXFLAGS ?= -O2 -g
LDFLAGS  ?=
LDLIBS   := -lpthread

# The AVX2 translation unit is the only one built for anything above baseline
# x86-64, and it is entered solely through the runtime probe in bitpack.cpp --
# so the binary still starts on a machine without AVX2.
AVX2FLAGS := -mavx2

COMMON_SRC := \
	common/src/sdi_format.cpp \
	common/src/bitpack.cpp \
	common/src/crc.cpp \
	common/src/sdi_raster.cpp \
	common/src/hbrmt.cpp \
	common/src/net_interfaces.cpp \
	common/src/net_multicast.cpp \
	common/src/pacer.cpp \
	common/src/pcap_source.cpp \
	common/src/replay_engine.cpp \
	common/src/stats_server.cpp \
	common/src/settings.cpp \
	common/src/platform.cpp \
	common/src/status_text.cpp

NMOS_SRC := \
	nmos/src/json.cpp \
	nmos/src/http.cpp \
	nmos/src/mdns.cpp \
	nmos/src/mdns_posix.cpp \
	nmos/src/uuid.cpp \
	nmos/src/nmos_node.cpp \
	nmos/src/status_text.cpp

CLI_SRC  := tools/replay_cli.cpp
AVX2_SRC := common/src/bitpack_avx2.cpp
TEST_SRC := $(wildcard tests/*.cpp)

SRC  := $(COMMON_SRC) $(NMOS_SRC) $(CLI_SRC)
OBJ  := $(patsubst %.cpp,$(BUILD)/obj/%.o,$(SRC))
AOBJ := $(patsubst %.cpp,$(BUILD)/obj/%.o,$(AVX2_SRC))
DEPS := $(OBJ:.o=.d) $(AOBJ:.o=.d)

# The library objects, i.e. everything but the CLI's own main().
LIB_OBJ   := $(patsubst %.cpp,$(BUILD)/obj/%.o,$(COMMON_SRC) $(NMOS_SRC))
TEST_OBJ  := $(patsubst %.cpp,$(BUILD)/obj/%.o,$(TEST_SRC))
TEST_DEPS := $(TEST_OBJ:.o=.d)

TARGET      := $(BUILD)/bin/replay_cli
TEST_TARGET := $(BUILD)/bin/pcapreplay_tests

.PHONY: all test debug asan clean install

all: $(TARGET)

debug: CXXFLAGS := -O0 -g3 -fno-omit-frame-pointer
debug: $(TARGET)

# Worth having wired in: the hot paths here are raw pointer arithmetic over
# multi-megabyte frame buffers, which is exactly what ASan is good at and
# exactly where a mistake is otherwise a silent corruption on the wire.
asan: CXXFLAGS := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
asan: LDFLAGS  += -fsanitize=address,undefined
asan: $(TARGET)

$(TARGET): $(OBJ) $(AOBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "built $@"

$(AOBJ): $(BUILD)/obj/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) $(WARN) $(CXXFLAGS) $(AVX2FLAGS) $(INCLUDES) -MMD -MP -c $< -o $@

$(BUILD)/obj/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) $(WARN) $(CXXFLAGS) $(INCLUDES) -MMD -MP -c $< -o $@

# tests/ needs mdns_internal.h from nmos/src: the DNS-SD record interpretation
# shared by both platforms is worth testing directly, not only through a live
# browse that needs a network.
$(TEST_OBJ): $(BUILD)/obj/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) $(WARN) $(CXXFLAGS) $(INCLUDES) -Itests -Inmos/src -MMD -MP -c $< -o $@

$(TEST_TARGET): $(TEST_OBJ) $(LIB_OBJ) $(AOBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: $(TEST_TARGET)
	$(TEST_TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/replay_cli
	@echo "installed $(DESTDIR)$(PREFIX)/bin/replay_cli"
	@echo
	@echo "Optional, for real-time packet pacing without running as root:"
	@echo "    sudo setcap cap_sys_nice=eip $(DESTDIR)$(PREFIX)/bin/replay_cli"

clean:
	rm -rf $(BUILD)

-include $(DEPS) $(TEST_DEPS)
