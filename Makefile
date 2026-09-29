prog :=rustad

cargo := $(shell command -v cargo 2> /dev/null)
cargo_v := $(shell cargo -V| cut -d ' ' -f 2)
rustup := $(shell command -v rustup 2> /dev/null)

# ──────────────────────────────────────────────────────────
# RUSTFLAGS for maximum static, stripped Windows GNU builds
# ──────────────────────────────────────────────────────────
# -C target-feature=+crt-static   : link CRT statically (no msvcrt/ucrt DLL dependency)
# -C link-arg=-s                  : pass -s to linker (strip all symbols from output)
# -C link-arg=-Wl,--gc-sections   : garbage collect unused sections
# -C link-arg=-Wl,--strip-all     : strip all symbols and relocation info
# -C link-arg=-Wl,--strip-debug   : strip debug sections
# -C link-arg=-Wl,-S              : strip debugger symbols
# -C link-arg=-Wl,--build-id=none : no .note.gnu.build-id section
# -C link-arg=-Wl,--no-insert-timestamp : zero PE timestamp (reproducible)
# -C debuginfo=0                  : no debug info generated
# -C opt-level=z                  : optimize for smallest binary size
# -C link-arg=-static             : force fully static linking
# -C link-arg=-Wl,--enable-stdcall-fixup : compatibility with older Windows
# -C link-arg=-Wl,--subsystem,console:5.1 : PE subsystem 5.1 = Windows XP minimum (x86)
# -C link-arg=-Wl,--subsystem,console:5.2 : PE subsystem 5.2 = Windows XP x64 minimum
# NOTE: relocation-model=static causes linker overflow on large x64 binaries, omitted
# NOTE: api-ms-win-crt-* DLLs from Rust's pre-built GNU stdlib require Win10+ or UCRT redist on Win7/8

WIN_COMMON_FLAGS := \
	-C target-feature=+crt-static \
	-C link-arg=-s \
	-C link-arg=-static \
	-C link-arg=-Wl,--gc-sections \
	-C link-arg=-Wl,--strip-all \
	-C link-arg=-Wl,--strip-debug \
	-C link-arg=-Wl,--build-id=none \
	-C link-arg=-Wl,--no-insert-timestamp \
	-C link-arg=-Wl,--enable-stdcall-fixup \
	-C debuginfo=0 \
	-C opt-level=z

WIN_X64_FLAGS := $(WIN_COMMON_FLAGS) -C link-arg=-Wl,--subsystem,console:5.2
WIN_X86_FLAGS := $(WIN_COMMON_FLAGS) -C link-arg=-Wl,--subsystem,console:5.1

check_cargo:
  ifndef cargo
    $(error cargo is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  else
	@echo "Make sure your cargo version is up to date! Current version is $(cargo_v)"
  endif

check_rustup:
  ifndef rustup
    $(error rustup is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  endif

update_rustup:
	rustup update

release: check_cargo
	cargo build --release
	cp target/release/$(prog) .
	@echo -e "[+] You can find \033[1;32m$(prog)\033[0m in your current folder."

debug: check_cargo
	cargo build
	cp target/debug/$(prog) ./$(prog)_debug
	@echo -e "[+] You can find \033[1;32m$(prog)_debug\033[0m in your current folder."

doc: check_cargo
	cargo doc --open --no-deps

install: check_cargo
	cargo install --path .
	@echo "[+] rusthound installed!"

uninstall:
	@cargo uninstall rusthound

clean:
	rm target -rf

# ──────────────────────────────────────────────────────────
# Windows builds - fully static, stripped, broad compat
# ──────────────────────────────────────────────────────────
install_windows_deps: update_rustup
	@rustup target add x86_64-pc-windows-gnu
	@rustup target add i686-pc-windows-gnu

build_windows_x64:
	RUSTFLAGS="$(WIN_X64_FLAGS)" cargo build --release --target x86_64-pc-windows-gnu --features nogssapi --no-default-features
	@cp target/x86_64-pc-windows-gnu/release/$(prog).exe ./$(prog)_x64.exe
	@# Double-strip: objcopy removes PE debug directory, COFF symbol table, .pdata, .xdata
	@x86_64-w64-mingw32-strip --strip-all --strip-unneeded ./$(prog)_x64.exe 2>/dev/null || strip --strip-all ./$(prog)_x64.exe 2>/dev/null || true
	@echo -e "[+] You can find \033[1;32m$(prog)_x64.exe\033[0m (static, stripped) in your current folder."
	@ls -lh ./$(prog)_x64.exe 2>/dev/null || dir ./$(prog)_x64.exe 2>/dev/null

build_windows_x86:
	RUSTFLAGS="$(WIN_X86_FLAGS)" cargo build --release --target i686-pc-windows-gnu --features nogssapi --no-default-features
	@cp target/i686-pc-windows-gnu/release/$(prog).exe ./$(prog)_x86.exe
	@i686-w64-mingw32-strip --strip-all --strip-unneeded ./$(prog)_x86.exe 2>/dev/null || strip --strip-all ./$(prog)_x86.exe 2>/dev/null || true
	@echo -e "[+] You can find \033[1;32m$(prog)_x86.exe\033[0m (static, stripped) in your current folder."
	@ls -lh ./$(prog)_x86.exe 2>/dev/null || dir ./$(prog)_x86.exe 2>/dev/null

build_windows_noargs:
	RUSTFLAGS="$(WIN_X64_FLAGS)" cargo build --release --target x86_64-pc-windows-gnu --features noargs,nogssapi --no-default-features
	@cp target/x86_64-pc-windows-gnu/release/$(prog).exe ./$(prog)_noargs.exe
	@x86_64-w64-mingw32-strip --strip-all --strip-unneeded  ./$(prog)_noargs.exe 2>/dev/null || strip --strip-all ./$(prog)_noargs.exe 2>/dev/null || true
	@echo -e "[+] You can find \033[1;32m$(prog)_noargs.exe\033[0m (static, stripped, no args) in your current folder."

# Combined targets
windows: check_rustup install_windows_deps build_windows_x64
windows_x64: check_rustup install_windows_deps build_windows_x64
windows_x86: check_rustup install_windows_deps build_windows_x86
windows_noargs: check_rustup install_windows_deps build_windows_noargs

windows_all: check_rustup install_windows_deps build_windows_x64 build_windows_x86 build_windows_noargs
	@echo -e "[+] All Windows builds complete!"

# ──────────────────────────────────────────────────────────
# Linux builds
# ──────────────────────────────────────────────────────────
install_linux_musl_deps:
	@rustup target add x86_64-unknown-linux-musl

build_linux_musl:
	cross build --target x86_64-unknown-linux-musl --release --features nogssapi --no-default-features
	cp target/x86_64-unknown-linux-musl/release/$(prog) ./$(prog)_musl
	@echo -e "[+] You can find \033[1;32m$(prog)_musl\033[0m in your current folder."

linux_musl: check_rustup install_cross build_linux_musl

install_linux_deps: update_rustup
	@rustup target add x86_64-unknown-linux-gnu

build_linux_aarch64:
	cross build --target aarch64-unknown-linux-gnu --release --features nogssapi --no-default-features
	cp target/aarch64-unknown-linux-gnu/release/$(prog) ./$(prog)_aarch64
	@echo -e "[+] You can find \033[1;32m$(prog)_aarch64\033[0m in your current folder."

linux_aarch64: check_rustup install_cross build_linux_aarch64

build_linux_x86_64:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --features nogssapi --target x86_64-unknown-linux-gnu --no-default-features
	cp target/x86_64-unknown-linux-gnu/release/$(prog) ./$(prog)_x86_64
	@echo -e "[+] You can find \033[1;32m$(prog)_x86_64\033[0m in your current folder."

linux_x86_64: check_rustup install_linux_deps build_linux_x86_64

# ──────────────────────────────────────────────────────────
# macOS builds
# ──────────────────────────────────────────────────────────
install_macos_deps:
	@sudo git clone https://github.com/tpoechtrager/osxcross /usr/local/bin/osxcross || exit
	@sudo wget -P /usr/local/bin/osxcross/ -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.10.sdk.tar.xz && sudo mv /usr/local/bin/osxcross/MacOSX10.10.sdk.tar.xz /usr/local/bin/osxcross/tarballs/
	@sudo UNATTENDED=yes OSX_VERSION_MIN=10.7 /usr/local/bin/osxcross/build.sh
	@sudo chmod 775 /usr/local/bin/osxcross/ -R
	@export PATH="/usr/local/bin/osxcross/target/bin:$$PATH"

build_macos:
	@export PATH="/usr/local/bin/osxcross/target/bin:$$PATH"
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-apple-darwin --features nogssapi --no-default-features
	cp target/x86_64-apple-darwin/release/$(prog) ./$(prog)_MacOS
	@echo -e "[+] You can find \033[1;32m$(prog)_MacOS\033[0m in your current folder."

macos: build_macos

install_cross:
	@cargo install --version 0.1.16 cross

arm_musl: check_rustup install_cross
	cross build --target arm-unknown-linux-musleabi --release --features nogssapi --no-default-features
	cp target/arm-unknown-linux-musleabi/release/$(prog) ./$(prog)_arm_musl
	@echo -e "[+] You can find \033[1;32m$(prog)_arm_musl\033[0m in your current folder."

armv7: check_rustup install_cross
	cross build --target armv7-unknown-linux-gnueabihf --release --features nogssapi --no-default-features
	cp target/armv7-unknown-linux-gnueabihf/release/$(prog) ./$(prog)_armv7
	@echo -e "[+] You can find \033[1;32m$(prog)_armv7\033[0m in your current folder."

help:
	@echo ""
	@echo "Default:"
	@echo "usage: make install"
	@echo "usage: make uninstall"
	@echo "usage: make debug"
	@echo "usage: make release"
	@echo ""
	@echo "Static Windows (fully static, stripped, no DLL deps):"
	@echo "usage: make windows        # x64 static"
	@echo "usage: make windows_x64    # x64 static"
	@echo "usage: make windows_x86    # x86 static (runs on 32-bit Windows)"
	@echo "usage: make windows_noargs # x64 static, auto-detect domain"
	@echo "usage: make windows_all    # all three Windows builds"
	@echo ""
	@echo "Static Linux:"
	@echo "usage: make linux_musl     # x86_64 musl static"
	@echo "usage: make linux_x86_64   # x86_64 glibc static CRT"
	@echo "usage: make linux_aarch64  # aarch64 cross"
	@echo "usage: make arm_musl       # ARM musl static"
	@echo "usage: make armv7          # ARMv7 cross"
	@echo ""
	@echo "macOS:"
	@echo "usage: make macos"
	@echo ""
	@echo "Dependencies:"
	@echo "usage: make install_windows_deps"
	@echo "usage: make install_linux_musl_deps"
	@echo "usage: make install_macos_deps"
	@echo ""
