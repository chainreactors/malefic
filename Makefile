# <build command>:<target>
TARGETS := \
	windows_x64:x86_64-pc-windows-gnu \
	windows_x32:i686-pc-windows-gnu \
	linux_x64:x86_64-unknown-linux-gnu \
	linux_x32:i686-unknown-linux-gnu \
	darwin_x64:x86_64-apple-darwin \
	darwin_arm:aarch64-apple-darwin
# Release build command
CARGO_RELEASE := cargo build --release -v -p malefic --target

EDITION ?= community
config:
	cargo run --release -p malefic-config $(EDITION)

FEATURES ?=
profile_module:
	cargo build --release -p malefic-modules --features $(FEATURES)

# Define rule
define build_single
.ONESHELL:
$(1): config
	echo "start to build [$(2)]"
	rustup target add $(2)
ifeq ($(findstring darwin, $(2)),darwin)
	bash /build/build-osxcross.sh
	export CC=o64-clang
	export CXX=o64-clang++
	export CROSS_COMPILE=o64-
endif
ifneq ($(findstring windows, $(2)),windows)
	export CARGO_PROFILE_RELEASE_LTO=true
endif
	$(CARGO_RELEASE) $(2)
endef
$(foreach target,$(TARGETS),$(eval $(call build_single,$(firstword $(subst :, ,$(target))),$(lastword $(subst :, ,$(target))))))

# build all
all: $(foreach target,$(TARGETS),$(firstword $(subst :, ,$(target))))

clean:
	cargo clean