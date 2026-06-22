# Genjutsu - MinGW Makefile
# Requires: mingw-w64, cmake (or use CMakeLists.txt for full build)

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Os -s -fvisibility=hidden -fno-exceptions
LDFLAGS  ?= -static-libgcc -static-libstdc++ -lntdll -lkernel32 -lole32 -lcomctl32

ARCH    ?= x64
ifneq ($(ARCH),x64)
CXXFLAGS += -m32
LDFLAGS  += -m32
endif

SRC_DIR   := src
BUILD_DIR := build/mingw/$(ARCH)
BIN_DIR   := $(BUILD_DIR)/bin

ENGINE_SRCS := \
    $(SRC_DIR)/engine/Main.cpp \
    $(SRC_DIR)/engine/whp/CodePatcher.cpp \
    $(SRC_DIR)/engine/whp/CpuidHandler.cpp \
    $(SRC_DIR)/engine/whp/ExceptionHandler.cpp \
    $(SRC_DIR)/engine/whp/ExitDispatcher.cpp \
    $(SRC_DIR)/engine/whp/EptHook.cpp \
    $(SRC_DIR)/engine/whp/KuserHook.cpp \
    $(SRC_DIR)/engine/whp/KuserSync.cpp \
    $(SRC_DIR)/engine/whp/MagicCpuid.cpp \
    $(SRC_DIR)/engine/whp/MsrHandler.cpp \
    $(SRC_DIR)/engine/whp/MsrPatcher.cpp \
    $(SRC_DIR)/engine/whp/Partition.cpp \
    $(SRC_DIR)/engine/whp/RdtscHandler.cpp \
    $(SRC_DIR)/engine/whp/ThreadScheduler.cpp \
    $(SRC_DIR)/engine/whp/VcpuManager.cpp \
    $(SRC_DIR)/engine/sogen/CryptoEmu.cpp \
    $(SRC_DIR)/engine/sogen/FileEmu.cpp \
    $(SRC_DIR)/engine/sogen/MemoryEmu.cpp \
    $(SRC_DIR)/engine/sogen/ObjectEmu.cpp \
    $(SRC_DIR)/engine/sogen/PeLoader.cpp \
    $(SRC_DIR)/engine/sogen/ProcessEmu.cpp \
    $(SRC_DIR)/engine/sogen/RegistryEmu.cpp \
    $(SRC_DIR)/engine/sogen/SectionEmu.cpp \
    $(SRC_DIR)/engine/sogen/SoGenEmulator.cpp \
    $(SRC_DIR)/engine/sogen/SyscallDispatcher.cpp \
    $(SRC_DIR)/engine/sogen/SyscallNames.cpp \
    $(SRC_DIR)/engine/sogen/ThreadManager.cpp \
    $(SRC_DIR)/engine/sogen/TimingEmu.cpp \
    $(SRC_DIR)/engine/sogen/VirtualState.cpp \
    $(SRC_DIR)/engine/profile/CpuProfile.cpp \
    $(SRC_DIR)/engine/profile/GpuProfile.cpp \
    $(SRC_DIR)/engine/profile/StorageProfile.cpp \
    $(SRC_DIR)/engine/profile/TimingProfile.cpp \
    $(SRC_DIR)/engine/proxy/Fallthrough.cpp \
    $(SRC_DIR)/engine/proxy/GpuBridge.cpp \
    $(SRC_DIR)/engine/proxy/IatPatch.cpp \
    $(SRC_DIR)/engine/proxy/InlineHook.cpp \
    $(SRC_DIR)/engine/proxy/ModuleCloak.cpp \
    $(SRC_DIR)/engine/proxy/ProxyBase.cpp \
    $(SRC_DIR)/engine/proxy/SoGenBridge.cpp \
    $(SRC_DIR)/launcher/ConfigParser.cpp \
    $(SRC_DIR)/engine/log/Logger.cpp

LAUNCHER_SRCS := \
    $(SRC_DIR)/launcher/Main.cpp \
    $(SRC_DIR)/launcher/ConfigParser.cpp \
    $(SRC_DIR)/launcher/ProcessUtils.cpp \
    $(SRC_DIR)/launcher/WhpDetection.cpp \
    $(SRC_DIR)/engine/log/Logger.cpp

ENGINE_OBJS    := $(ENGINE_SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
LAUNCHER_OBJS  := $(LAUNCHER_SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

.PHONY: all clean engine launcher dirs

all: dirs engine launcher

dirs:
	@mkdir -p $(BUILD_DIR)/engine/whp $(BUILD_DIR)/engine/sogen $(BUILD_DIR)/engine/profile $(BUILD_DIR)/engine/proxy $(BUILD_DIR)/engine/log $(BUILD_DIR)/engine/launcher $(BUILD_DIR)/launcher $(BIN_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/engine -I$(SRC_DIR)/engine/log -I$(SRC_DIR)/launcher -DGENJUTSU_MINGW -c -o $@ $<

engine: $(ENGINE_OBJS)
	$(CXX) -shared -o $(BIN_DIR)/engine.dll $^ $(LDFLAGS)
	@echo "  -> $(BIN_DIR)/engine.dll"

launcher: $(LAUNCHER_OBJS)
	$(CXX) -o $(BIN_DIR)/launcher.exe $^ $(LDFLAGS)
	@echo "  -> $(BIN_DIR)/launcher.exe"

clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned."
