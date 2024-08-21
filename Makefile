# <build command>=<target>
TARGETS := \
	darwin64=x86_64-apple-darwin \
	darwin_aarch64=aarch64-apple-darwin \
	win64=x86_64-pc-windows-gnu \
	win32=i686-pc-windows-gnu \
	linux64=x86_64-unknown-linux-gnu \
	linux32=i686-unknown-linux-gnu

# Release build command
CARGO_RELEASE := cargo build --release -p malefic --target
profile_community:
	cargo run --release -p malefic-config community
#	FEATURES ?=
#	profile_community_module:
#		cargo build --release -p malefic-modules --features $(FEATURES)

# Define rule
define single_build
build_$(1): profile_community
	echo "start to build [$(2)]"
	@if [ "$(1)" = "darwin_aarch64" ] || [ "$(1)" = "darwin64" ]; then \
		CC=o64-clang CXX=o64-clang++ CROSS_COMPILE=o64- $(CARGO_RELEASE) $(2); \
	else \
		$(CARGO_RELEASE) $(2);\
	fi

	@if [ "$(1)" = "win64" ] || [ "$(1)" = "win32" ] ; then \
		strip ./target/$(2)/release/malefic.exe; \
	else \
		strip ./target/$(2)/release/malefic; \
	fi
endef

# Generate all rules
$(foreach target,$(TARGETS),$(eval $(call single_build,$(firstword $(subst =, ,$(target))),$(lastword $(subst =, ,$(target))))))

# build all
all: $(foreach target,$(TARGETS),build_$(firstword $(subst =, ,$(target))))

clean:
	cargo clean