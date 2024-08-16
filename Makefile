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
debug: profile_professional
	cargo run -p malefic