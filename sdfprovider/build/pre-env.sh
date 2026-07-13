#!/bin/bash

echo "========== prepare env begin =========="

ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo "ERROR: only supports build on x86_64 system."
    exit 1
fi

toolchain_base=/tmp
target_dir=target/antrun
# Download the cross-compilation toolchain first
toolchain_name=gcc-arm-8.3-2019.03-x86_64-aarch64-linux-gnu
toolchain_pkg=$toolchain_name.tar.xz
toolchain_url=https://mirrors.tuna.tsinghua.edu.cn/armbian-releases/_toolchain/$toolchain_pkg

if [ ! -f "${toolchain_base}/${toolchain_pkg}" ]; then
    echo "begin to download toolchain: $toolchain_pkg......"
    wget -c -P ${toolchain_base} $toolchain_url
fi

if [ $? -ne 0 ] || [ ! -f "${toolchain_base}/${toolchain_pkg}" ]; then
    echo "ERROR: Failed to download toolchain from ${toolchain_url}"
    exit 1
fi

if [ ! -d "${toolchain_base}/${toolchain_name}" ]; then
    echo "begin to tar -xf $toolchain_pkg......"
    tar -xf ${toolchain_base}/$toolchain_pkg -C ${toolchain_base}
fi

EXECUTABLE_X86_64=gcc
EXECUTABLE_AARCH64=${toolchain_base}/$toolchain_name/bin/aarch64-linux-gnu-gcc

LIBRARY_PATH_X86="${target_dir}/cryptocard/x86_64"
LIBRARY_PATH_AARCH64="${target_dir}/cryptocard/aarch64"

[ ! -d "$LIBRARY_PATH_X86" ] && mkdir -p "$LIBRARY_PATH_X86"
[ ! -d "$LIBRARY_PATH_AARCH64" ] && mkdir -p "$LIBRARY_PATH_AARCH64"

# Compile x86 libcrypto_card_sdk.so for build
$EXECUTABLE_X86_64 -fPIC -shared -o ${target_dir}/libcrypto_card_sdk.so build/build_crypto_so.c -I src/main/native/cryptocard/
mv -f ${target_dir}/libcrypto_card_sdk.so $LIBRARY_PATH_X86

# Compile aarch64 libcrypto_card_sdk.so for build
$EXECUTABLE_AARCH64 -fPIC -shared -o ${target_dir}/libcrypto_card_sdk.so build/build_crypto_so.c -I src/main/native/cryptocard/
mv -f ${target_dir}/libcrypto_card_sdk.so $LIBRARY_PATH_AARCH64

# create env properties for maven install
echo "begin to create env properties...."
cat > ${target_dir}/env.properties << EOF
SDF_EXECUTABLE_X86_64=$EXECUTABLE_X86_64
SDF_EXECUTABLE_AARCH64=$EXECUTABLE_AARCH64
SDF_LIBRARY_PATH_X86_64=$LIBRARY_PATH_X86
SDF_LIBRARY_PATH_AARCH64=$LIBRARY_PATH_AARCH64
EOF

echo "========== prepare env finished =========="