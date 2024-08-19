.ONESHELL:
clean:
	cargo clean

.ONESHELL:
profile_community:
	cargo run --release -p malefic-config community

.ONESHELL:
commuinty_exe: profile_community
	cargo build --release -p malefic

.ONESHELL:
commuinty_run: profile_community
	cargo run --release -p malefic

.ONESHELL:
community_win64: profile_community
	cargo build --release -p malefic --target x86_64-pc-windows-gnu

.ONESHELL:
community_win32: profile_community
	cargo build --release -p malefic --target i686-pc-windows-gnu	

.ONESHELL:
community_linux64: profile_community
	cargo build --release -p malefic --target x86_64-unknown-linux-gnu

.ONESHELL:
community_linux32: profile_community
	cargo build --release -p malefic --target i686-unknown-linux-gnu

.ONESHELL:
community_darwin64: profile_community
	cargo build --release -p malefic --target x86_64-apple-darwin

.ONESHELL:
community_darwin_arm64: profile_community
	cargo build --release -p malefic --target aarch64-apple-darwin

.ONESHELL:
debug_community: profile_community
	cargo run -p malefic
