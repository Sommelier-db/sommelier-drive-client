cargo +nightly build --release &&
rustup run nightly cbindgen --config cbindgen.toml --crate sommelier-drive-client --output sommelier_drive_client.h