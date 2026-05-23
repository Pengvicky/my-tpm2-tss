ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
THIRD_PARTY_DIR ?= $(abspath $(ROOT_DIR)/..)

OPENHITLS_DIR ?= $(THIRD_PARTY_DIR)/openhitls
PQCP_DIR ?= $(THIRD_PARTY_DIR)/pqcp
PQMAGIC_DIR ?= $(THIRD_PARTY_DIR)/pqmagic
SECUREC_DIR ?= $(OPENHITLS_DIR)/platform/Secure_C

BUILD_DIR ?= $(ROOT_DIR)/build
OPENHITLS_BUILD ?= $(OPENHITLS_DIR)/build
PQCP_BUILD ?= $(BUILD_DIR)/third_party/pqcp
PQMAGIC_BUILD ?= $(BUILD_DIR)/third_party/pqmagic

BIN_DIR := $(BUILD_DIR)/bin
LIB_DIR := $(BUILD_DIR)/lib
OBJ_DIR := $(BUILD_DIR)/obj
STAMP_DIR := $(BUILD_DIR)/stamps

CC ?= $(CROSS_COMPILE)gcc
AR ?= $(CROSS_COMPILE)ar
RANLIB ?= $(CROSS_COMPILE)ranlib
CC_ABS := $(shell command -v $(CC) 2>/dev/null || printf '%s' '$(CC)')
AR_ABS := $(shell command -v $(AR) 2>/dev/null || printf '%s' '$(AR)')
RANLIB_ABS := $(shell command -v $(RANLIB) 2>/dev/null || printf '%s' '$(RANLIB)')

BITS ?= 64
SYSTEM ?= linux
NPROC ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)

CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
CMAKE_ARGS ?=
BOUNDSCHECK_LIB_NAME ?= boundscheck
PQMAGIC_USE_NATIVE_OPTIMIZATION ?= OFF

OPENHITLS_STAMP := $(STAMP_DIR)/openhitls.stamp
PQMAGIC_STAMP := $(STAMP_DIR)/pqmagic.stamp
PQCP_STAMP := $(STAMP_DIR)/pqcp.stamp

COMMON_INCLUDES := \
	-I$(ROOT_DIR)/src/common \
	-I$(PQMAGIC_DIR)/include

PQMAGIC_INCLUDES := $(COMMON_INCLUDES)
PQCP_INCLUDES := \
	$(COMMON_INCLUDES) \
	-I$(PQCP_DIR)/include \
	-I$(PQCP_DIR)/src/scloudplus/include \
	-I$(OPENHITLS_DIR)/include/bsl \
	-I$(OPENHITLS_DIR)/include/crypto

OPENHITLS_LIB_DIR := $(OPENHITLS_BUILD)
SECUREC_LIB_DIR := $(SECUREC_DIR)/lib
STAGED_BOUNDSCHECK_LIB := $(LIB_DIR)/lib$(BOUNDSCHECK_LIB_NAME).so

PQMAGIC_LIBS := -L$(PQMAGIC_BUILD) -lpqmagic_std -lm
PQCP_LIBS := \
	-L$(PQCP_BUILD) \
	-L$(OPENHITLS_LIB_DIR) \
	-L$(SECUREC_LIB_DIR) \
	-Wl,--start-group \
	-lpqcp_provider -lhitls_crypto -lhitls_tls -lhitls_pki -lhitls_auth -lhitls_bsl -l$(BOUNDSCHECK_LIB_NAME) \
	-Wl,--end-group \
	-lpthread -lm -ldl
PQCP_RPATH := -Wl,-rpath,'$$ORIGIN/../lib'

COMMON_OBJS := \
	$(OBJ_DIR)/common/file_util.o \
	$(OBJ_DIR)/common/pq_alg_info.o \
	$(OBJ_DIR)/common/tpm_pq_blob.o

TOOLS := \
	$(BIN_DIR)/tpm_pq_pubtool \
	$(BIN_DIR)/pqmagic_aigis_tool \
	$(BIN_DIR)/pqcp_scloud_tool

.PHONY: all third_party tools openhitls pqmagic pqcp clean help

all: third_party tools

help:
	@echo "Targets:"
	@echo "  make all          Build openhitls, pqmagic, pqcp, and all local tools"
	@echo "  make third_party  Build openhitls, pqmagic, and pqcp only"
	@echo "  make tools        Build tpm_pq_pubtool, pqmagic_aigis_tool, pqcp_scloud_tool"
	@echo "  make clean        Remove pqc_soft_demo build outputs"
	@echo ""
	@echo "Common variables:"
	@echo "  CROSS_COMPILE, CC, AR, RANLIB"
	@echo "  BUILD_DIR=$(BUILD_DIR)"
	@echo "  OPENHITLS_BUILD=$(OPENHITLS_BUILD)"
	@echo "  BITS=$(BITS) SYSTEM=$(SYSTEM) NPROC=$(NPROC)"
	@echo "  PQMAGIC_USE_NATIVE_OPTIMIZATION=$(PQMAGIC_USE_NATIVE_OPTIMIZATION)"
	@echo "  CMAKE_ARGS=<extra flags passed to third-party CMake invocations>"

third_party: openhitls pqmagic pqcp

tools: $(TOOLS)

openhitls: $(OPENHITLS_STAMP)

pqmagic: $(PQMAGIC_STAMP)

pqcp: $(PQCP_STAMP)

$(BIN_DIR) $(LIB_DIR) $(OBJ_DIR) $(OBJ_DIR)/common $(STAMP_DIR):
	mkdir -p $@

$(STAGED_BOUNDSCHECK_LIB): $(OPENHITLS_STAMP) | $(LIB_DIR)
	cp $(SECUREC_LIB_DIR)/lib$(BOUNDSCHECK_LIB_NAME).so $@

$(OPENHITLS_STAMP): | $(STAMP_DIR)
	$(MAKE) -C $(SECUREC_DIR) CC="$(CC)" AR="$(AR)" RANLIB="$(RANLIB)" -j$(NPROC)
	mkdir -p $(OPENHITLS_BUILD)
	cd $(OPENHITLS_BUILD) && CC="$(CC)" AR="$(AR)" RANLIB="$(RANLIB)" python3 ../configure.py --enable all --lib_type static --bits=$(BITS) --system=$(SYSTEM)
	cd $(OPENHITLS_BUILD) && cmake .. -DBUILD_DIR=$(OPENHITLS_BUILD) -DCMAKE_C_COMPILER=$(CC_ABS) -DCMAKE_AR=$(AR_ABS) -DCMAKE_RANLIB=$(RANLIB_ABS) $(CMAKE_ARGS)
	cd $(OPENHITLS_BUILD) && $(MAKE) -j$(NPROC)
	touch $@

$(PQMAGIC_STAMP): $(OPENHITLS_STAMP) | $(STAMP_DIR)
	rm -rf $(PQMAGIC_BUILD)
	mkdir -p $(PQMAGIC_BUILD)
	cd $(PQMAGIC_BUILD) && cmake $(PQMAGIC_DIR) -DCMAKE_C_COMPILER=$(CC_ABS) -DCMAKE_AR=$(AR_ABS) -DCMAKE_RANLIB=$(RANLIB_ABS) -DPQMAGIC_USE_NATIVE_OPTIMIZATION=$(PQMAGIC_USE_NATIVE_OPTIMIZATION) -DUSE_SM3=ON -DENABLE_AIGIS_SIG=ON -DENABLE_ML_DSA=ON -DENABLE_TEST=OFF -DENABLE_BENCH=OFF $(CMAKE_ARGS)
	cd $(PQMAGIC_BUILD) && cmake --build . --target pqmagic_static_target -j$(NPROC)
	touch $@

$(PQCP_STAMP): $(OPENHITLS_STAMP) | $(STAMP_DIR)
	ln -sfn ../../openhitls $(PQCP_DIR)/platform/openhitls
	rm -rf $(PQCP_BUILD)
	mkdir -p $(PQCP_BUILD)
	cd $(PQCP_BUILD) && cmake $(PQCP_DIR) -DCMAKE_C_COMPILER=$(CC_ABS) -DCMAKE_AR=$(AR_ABS) -DCMAKE_RANLIB=$(RANLIB_ABS) -DPQCP_LIB_TYPE=STATIC -DPQCP_ENABLE_TEST=OFF -DHITLS_ROOT_PATH=$(OPENHITLS_DIR) -DCMAKE_C_FLAGS="-DHITLS_CRYPTO_EAL -DHITLS_CRYPTO_PKEY -DHITLS_CRYPTO_MD -DHITLS_CRYPTO_PROVIDER -DHITLS_CRYPTO_SHA3 -DHITLS_CRYPTO_SHA2 -DHITLS_CRYPTO_BN -DHITLS_CRYPTO_ENTROPY -DHITLS_CRYPTO_DRBG -DHITLS_BSL_SAL_LINUX -DHITLS_THIRTY_TWO_BITS -DHITLS_CRYPTO_PROVIDER_LOAD -DPQCP_SCLOUDPLUS" $(CMAKE_ARGS)
	cd $(PQCP_BUILD) && cmake --build . --target pqcp_provider -j$(NPROC)
	touch $@

$(OBJ_DIR)/common/file_util.o: $(ROOT_DIR)/src/common/file_util.c $(ROOT_DIR)/src/common/file_util.h | $(OBJ_DIR)/common
	$(CC) $(CPPFLAGS) $(CFLAGS) $(COMMON_INCLUDES) -c $< -o $@

$(OBJ_DIR)/common/pq_alg_info.o: $(ROOT_DIR)/src/common/pq_alg_info.c $(ROOT_DIR)/src/common/pq_alg_info.h | $(OBJ_DIR)/common
	$(CC) $(CPPFLAGS) $(CFLAGS) $(COMMON_INCLUDES) -c $< -o $@

$(OBJ_DIR)/common/tpm_pq_blob.o: $(ROOT_DIR)/src/common/tpm_pq_blob.c $(ROOT_DIR)/src/common/tpm_pq_blob.h $(ROOT_DIR)/src/common/pq_alg_info.h | $(OBJ_DIR)/common
	$(CC) $(CPPFLAGS) $(CFLAGS) $(COMMON_INCLUDES) -c $< -o $@

$(OBJ_DIR)/tpm_pq_pubtool.o: $(ROOT_DIR)/src/tpm_pq_pubtool.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(COMMON_INCLUDES) -c $< -o $@

$(OBJ_DIR)/pqmagic_aigis_tool.o: $(ROOT_DIR)/src/pqmagic_aigis_tool.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PQMAGIC_INCLUDES) -c $< -o $@

$(OBJ_DIR)/pqcp_scloud_tool.o: $(ROOT_DIR)/src/pqcp_scloud_tool.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PQCP_INCLUDES) -c $< -o $@

$(BIN_DIR)/tpm_pq_pubtool: $(OBJ_DIR)/tpm_pq_pubtool.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ -o $@

$(BIN_DIR)/pqmagic_aigis_tool: $(PQMAGIC_STAMP) $(OBJ_DIR)/pqmagic_aigis_tool.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $(OBJ_DIR)/pqmagic_aigis_tool.o $(COMMON_OBJS) -o $@ $(PQMAGIC_LIBS)

$(BIN_DIR)/pqcp_scloud_tool: $(PQCP_STAMP) $(STAGED_BOUNDSCHECK_LIB) $(OBJ_DIR)/pqcp_scloud_tool.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $(OBJ_DIR)/pqcp_scloud_tool.o $(COMMON_OBJS) -o $@ $(PQCP_RPATH) $(PQCP_LIBS)

clean:
	rm -rf $(BUILD_DIR)
