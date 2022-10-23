cargo +nightly build --release &&
rustup run nightly cbindgen --config cbindgen.toml --crate sommelier-drive-client --output ./target/release/sommelier_drive_client.h