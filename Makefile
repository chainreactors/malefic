.ONESHELL:
clean:
	cargo clean

.ONESHELL:
profile_community:
	cargo run --release -p malefic-config community

.ONESHELL:
profile_professional:
	cargo run --release -p malefic-config professional

.ONESHELL:
commuinty_exe: profile_community
	cargo build --release -p malefic

.ONESHELL:
professional_exe: profile_professional
	cargo build --release -p malefic

.ONESHELL:
commuinty_run: profile_community
	cargo run --release -p malefic

.ONESHELL:
professional_run: profile_professional
	cargo run --release -p malefic

.ONESHELL:
community_win64: profile_community
	cargo build --release -p malefic --target x86_64-pc-windows-gnu

.ONESHELL:
community_win32: profile_community
	cargo build --release -p malefic --target i686-pc-windows-gnu	

.ONESHELL:
professional_win64: profile_community
	cargo build --release -p malefic --target x86_64-pc-windows-gnu

.ONESHELL:
professional_win32: profile_professional
	cargo build --release -p malefic --target i686-pc-windows-gnu

.ONESHELL:
professional_linux64: profile_professional
	cargo build --release -p malefic --target x86_64-unknown-linux-gnu

.ONESHELL:
professional_linux64: profile_professional
	cargo build --release -p malefic --target x86_64-unknown-linux-gnu

.ONESHELL:
community_linux32: profile_community
	cargo build --release -p malefic --target i686-unknown-linux-gnu

.ONESHELL:
professional_darwin64: profile_professional
	cargo build --release -p malefic --target x86_64-apple-darwin

.ONESHELL:
community_darwin64: profile_community
	cargo build --release -p malefic --target x86_64-apple-darwin

.ONESHELL:
community_darwin_arm64: profile_community
	cargo build --release -p malefic --target aarch64-apple-darwin

.ONESHELL:
professiona_darwin_arm64: profile_professional
	cargo build --release -p malefic --target aarch64-apple-darwin

.ONESHELL:
debug: profile_professional
	cargo run -p malefic

.ONESHELL:
debug_community: profile_community
	cargo run -p malefic
