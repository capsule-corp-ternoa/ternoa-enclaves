# UBUNTU
#ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

# ARCH LINUX
ARCH_LIBDIR ?= /lib/x86_64-linux-gnu

# NOTE: MUST BE "RELATIVE PATH" TO TEE BINARY
ENCLAVEDIR ?= "."
SELF_EXE = $(ENCLAVEDIR)/bin/sgx_server

SGX ?= 1
DEBUG ?= 0

.PHONY: all
all: sgx_server.manifest
ifeq ($(SGX),1)
all: sgx_server.manifest.sgx sgx_server.sig 
endif

ifeq ($(DEBUG),2)
GRAMINE_LOG_LEVEL = debug
else ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = warning
else
GRAMINE_LOG_LEVEL = error
endif

ifeq ($(SGX_DEV_BUILD),1)
MANIFEST_FILE = sgx_server_dev.manifest.template
else
MANIFEST_FILE = sgx_server.manifest.template
endif

sgx_server.manifest: $(MANIFEST_FILE)
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		-Denclave_dir=$(ENCLAVEDIR) \
		$< $@

sgx_server.manifest.sgx sgx_server.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: sgx_server.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif 

.PHONY: start-gramine-server
start-gramine-server: all
	$(GRAMINE) sgx_server \
		--domain $(SGX_DOMAIN) \
		--port $(SGX_PORT) \
		--verbose $(SGX_VERBOSITY) #>> $(ENCLAVEDIR)/enclave.log 2>&1 &

.PHONY: clean
clean:
	$(RM) -rf $(ENCLAVEDIR)/*.token $(ENCLAVEDIR)/*.sig $(ENCLAVEDIR)/*.manifest.sgx $(ENCLAVEDIR/)*.manifest $(ENCLAVEDIR)/result-* $(ENCLAVEDIR)/*.log

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock
