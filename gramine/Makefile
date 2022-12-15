# UBUNTU
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)


SELF_EXE = $(SGX_BASE_PATH)/bin/sgx_server
SGX ?= 1
DEBUG ?= 0


.PHONY: all
all: sgx_server.manifest
ifeq ($(SGX),1)
all: sgx_server.manifest.sgx sgx_server.sig sgx_server.token
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

sgx_server.manifest: sgx_server.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dquote_path=$(SGX_QUOTE_PATH) \
		-Dcertificates_path=$(SGX_CERT_PATH) \
		-Dself_exe=$(SELF_EXE) \
		-Dseal_path=$(SGX_SEAL_PATH) \
		$< $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
sgx_server.manifest.sgx sgx_server.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: sgx_server.manifest
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

.PHONY: start-gramine-server
start-gramine-server: all
	$(GRAMINE) sgx_server \
		--port $(SGX_PORT) \
		--certfile $(SGX_TLS_CERT) \
		--keyfile $(SGX_TLS_KEY) \
		--sealpath $(SGX_SEAL_PATH) \
		--identity $(SGX_IDENTITY) \
		--account $(SGX_OWNER_KEY) \
		> enclave.log 2>&1 &

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest result-* *.log

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock
