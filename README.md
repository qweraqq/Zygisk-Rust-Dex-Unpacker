## How to build

- Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

- Add Android Support
```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

- cargo-ndk & just
```bash
cargo install just
cargo install cargo-ndk
```

- export ANDROID_NDK_HOME `export ANDROID_NDK_HOME="PATH-TO/android-ndk-r27d`

- Build
```bash
just package
```