cargo +nightly build --release &&
rustup run nightly cbindgen --config cbindgen.toml --crate sommelier-drive-cryptos --output ./target/release/sommelier_drive_cryptos.h