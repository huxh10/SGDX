######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

Crypto_Library_Name := sgx_tcrypto

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Enclave_C_Files := $(wildcard enclave/*.c)
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I./shared_lib

Enclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := libenclave.so

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_C_Files := $(wildcard app/*.c)
App_Include_Paths := -I$(SGX_SDK)/include -I./app_lib -I./shared_lib

App_Compile_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_Compile_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_Compile_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_Compile_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -ljansson

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

#App_C_Objects := $(App_C_Files:.c=.o)

App_W_SGX := rs_w_sgx
App_Wo_SGX := rs_wo_sgx

######## Library Settings ########

Shared_Lib_C_Files := $(wildcard shared_lib/*.c)
Shared_Lib_Objects := $(Shared_Lib_C_Files:.c=.o)

#Trust_Lib_Objects := $(subst lib,enclave,$(Lib_Objects))
Shared_Lib_Include_Paths := -I$(SGX_SDK)/include -nostdinc -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport
Shared_Lib_Compile_Flags := $(SGX_COMMON_CFLAGS) -fvisibility=hidden -fpie -fstack-protector $(Shared_Lib_Include_Paths)

App_Lib_C_Files := $(wildcard app_lib/*.c)
App_Lib_Objects := $(App_Lib_C_Files:.c=.o)

######## ########

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

#ifeq ($(SGX_MODE), HW)
#ifneq ($(SGX_DEBUG), 1)
#ifneq ($(SGX_PRERELEASE), 1)
#Build_Mode = HW_RELEASE
#endif
#endif
#endif

ifeq ($(Build_Mode), HW_RELEASE)
all: enclave.so $(App_W_SGX) $(App_Wo_SGX)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the enclaves (enclave.so) first with your signing keys before you run the $(App_W_SGX) $(App_Wo_SGX) to launch and access the enclave."
	@echo "To sign the enclaves use the following commands:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <key> -enclave enclave.so -out <$(Enclave_Name)> -config enclave/enclave.config.xml"
	@echo "You can also sign the enclaves using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Enclave_Name) $(App_W_SGX) $(App_Wo_SGX)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

######## Library Objects ########

app_lib/%.o: app_lib/%.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

shared_lib/%.o: shared_lib/%.c
	@$(CC) $(Shared_Lib_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

######## App Objects ########
enclave/enclave_u.c enclave/enclave_u.h: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --use-prefix --untrusted ../enclave/enclave.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

app/enclave_u.o: enclave/enclave_u.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

app/server.o: app/server.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/rp_w_sgx.o: app/route_process_w_sgx.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/rp_wo_sgx.o: app/route_process_wo_sgx.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/msg_handler.wosgx.o: app/msg_handler.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/msg_handler.wsgx.o: app/msg_handler.c
	@$(CC) $(App_Compile_Flags) -DW_SGX -c $< -o $@
	@echo "CC  <=  $<"

app/main.wosgx.o: app/main.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/main.wsgx.o: app/main.c
	@$(CC) $(App_Compile_Flags) -DW_SGX -c $< -o $@
	@echo "CC  <=  $<"

$(App_Wo_SGX): app/main.wosgx.o app/msg_handler.wosgx.o app/rp_wo_sgx.o app/server.o $(App_Lib_Objects) $(Shared_Lib_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

$(App_W_SGX): app/enclave_u.o app/main.wsgx.o app/msg_handler.wsgx.o app/rp_w_sgx.o app/server.o $(App_Lib_Objects) $(Shared_Lib_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

enclave/enclave_t.c enclave/enclave_t.h: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --use-prefix --trusted ../enclave/enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/%.o: enclave/%.c
	@$(CC) -nostdinc $(Enclave_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

enclave.so: enclave/enclave_t.o $(Enclave_C_Objects) $(Shared_Lib_Objects)
	@$(CC) enclave/enclave_t.o $(Enclave_C_Objects) $(Shared_Lib_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Name): enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave enclave.so -out $@ -config enclave/enclave.config.xml
	@echo "SIGN =>  $@"

######## Clean ########
.PHONY: clean

clean:
	@rm -rf $(App_W_SGX) $(App_Wo_SGX) *.so *.a app/*.o enclave/*.o enclave/*_t.* enclave/*_u.* shared_lib/*.o app_lib/*.o
