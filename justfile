# Metadata
MODULE_ID := "zygisk-rust-dex-unpacker"
LIB_NAME := "zygisk_rust_dex_unpacker"
MODULE_NAME := "Zygisk Dex Unpacker (Rust)"
MODULE_AUTHOR := "qweraqq"

# Build settings
TARGET_DIR:="target"
BUILD_DIR:="magisk-module-zip"
ZIP_NAME:="zygisk-rust-dex-unpacker.zip"

# module.prop
MODULE_PROP:="""
id=zygisk-rust-dex-unpacker
name=Zygisk Dex Unpacker (Rust)
version=V1.0
versionCode=1
author=qweraqq
description=A simple Dex Unpacker based on Zygisk & developed in Rust
zygisk=true
"""

default: build

build: build-arm64

# aarch64
build-arm64:
    @cargo ndk -t arm64-v8a --platform=31 build --release

package: build
    @echo "Packaging Zygisk module..."
    
    @rm -rf {{BUILD_DIR}} {{ZIP_NAME}}

    @mkdir -p "{{BUILD_DIR}}/zygisk"
    
    @echo "{{MODULE_PROP}}" > "{{BUILD_DIR}}/module.prop"
    
    @cp "{{TARGET_DIR}}/aarch64-linux-android/release/lib{{LIB_NAME}}.so" "{{BUILD_DIR}}/zygisk/arm64-v8a.so"

    @echo "Creating {{ZIP_NAME}}..."
    @cd {{BUILD_DIR}} && zip -r9 ../{{ZIP_NAME}} .
    
    @echo "Packaged successfully: {{ZIP_NAME}}"

clean:
    @echo "Cleaning all build artifacts..."
    @rm -rf {{BUILD_DIR}} {{ZIP_NAME}}
    @cargo clean