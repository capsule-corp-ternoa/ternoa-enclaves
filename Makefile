ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SELF_EXE = target/release/sgx_server
SGX ?= 1
DEBUG ?= 0


.PHONY: all
all: $(SELF_EXE) sgx_server.manifest
ifeq ($(SGX),1)
all: sgx_server.manifest.sgx sgx_server.sig sgx_server.token
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

# Note that we're compiling in release mode regardless of the DEBUG setting passed
# to Make, as compiling in debug mode results in an order of magnitude's difference in
# performance that makes testing by running a benchmark with ab painful. The primary goal
# of the DEBUG setting is to control Gramine's loglevel.
-include $(SELF_EXE).d # See also: .cargo/config.toml
$(SELF_EXE): Cargo.toml
	cargo build --release

sgx_server.manifest: sgx_server.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
sgx_server.manifest.sgx sgx_server.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: sgx_server.manifest $(SELF_EXE)
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

sgx_server.token: sgx_server.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

SGX_SEAL_PATH=$NFT_SERCRETS_PATH SGX_OWNER_KEY=$TERNOA_ACCOUNT_KEY SGX_IDENTITY=$ENCLAVE_IDENTITY 

.PHONY: start-gramine-server
start-gramine-server: all
	$(GRAMINE) sgx_server \
		--port $(SGX_PORT) \
		--certfile $(SGX_TLS_CERT) \
		--keyfile $(SGX_TLS_KEY) \
		--secretpath $(SGX_SEAL_PATH) \
		--identity $(SGX_IDENTITY) \
		--account $(SGX_OWNER_KEY) \
		> enclave.log 2>&1 &

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest result-* *.log

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock
