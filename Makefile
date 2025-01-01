ifeq ($(OS),Windows_NT)
    is_win := 1
endif

# args for build or generate
release_version := v0.0.4
build_type :=
build_version := community
target_triple := x86_64-pc-windows-gnu
malefic_modules_features :=
malefic_pulse_arch := $(if $(findstring i686,$(target_triple)),x86,$(if $(findstring x86_64,$(target_triple)),x64,unknown))
malefic_pulse_os := $(if $(findstring win,$(target_triple)),win,$(if $(findstring linux,$(target_triple)),linux,$(if $(findstring macos,$(target_triple)),macos,unknown)))

# some path、command for build
MUTANT_PATH := ./target/release/malefic-mutant
MUTANT_PATH := $(if $(is_win),$(MUTANT_PATH).exe,$(MUTANT_PATH))
# generate command
GENERATE_CMD := $(MUTANT_PATH) generate $(if $(build_version),--version $(build_version),) $(if $(build_type),-s,)
# build command
BUILD_CMD := cargo build --release $(if $(target_triple),--target $(target_triple),)

base:
ifeq ($(wildcard $(MUTANT_PATH)),)
	@echo "mutant not exists, will build it"
	cargo build --release -p malefic-mutant
else
	@echo "mutant already exists"
endif

beacon: base
	$(GENERATE_CMD) beacon
	$(BUILD_CMD) -p malefic

bind: base
	$(GENERATE_CMD) bind
	$(BUILD_CMD) -p malefic

prelude: base
	$(GENERATE_CMD) prelude autorun.yaml
	$(BUILD_CMD) -p malefic-prelude

pulse: base
	$(GENERATE_CMD) pulse $(malefic_pulse_arch) $(malefic_pulse_os)
	$(BUILD_CMD) -p malefic-pulse

modules: base
	$(GENERATE_CMD) modules $(malefic_modules_features)
	$(BUILD_CMD) -p malefic-modules
