#!/bin/bash

set -x

echo "========== prepare env begin =========="

toolchain_cache_dir=/tmp
build_env_dir=target/antrun
sdk_stub_source_file=build/build_crypto_so.c
sdk_header_dir=src/main/native/cryptocard
sdk_stub_library_name=libcrypto_card_sdk.so

aarch64_toolchain_url=https://mirrors.tuna.tsinghua.edu.cn/armbian-releases/_toolchain/gcc-arm-8.3-2019.03-x86_64-aarch64-linux-gnu.tar.xz
x86_64_toolchain_url=https://registry.npmmirror.com/@zigpm/zig-linux-arm64/-/zig-linux-arm64-0.16.0.tgz

x86_64_sdk_library_dir=${SDF_LIBRARY_PATH_X86_64:-$build_env_dir/cryptocard/x86_64}
aarch64_sdk_library_dir=${SDF_LIBRARY_PATH_AARCH64:-$build_env_dir/cryptocard/aarch64}
sdk_stub_output_file=$build_env_dir/$sdk_stub_library_name

mkdir -p "$build_env_dir"

if [ -z "${SDF_LIBRARY_PATH_X86_64:-}" ]; then
    mkdir -p "$x86_64_sdk_library_dir"
else
    echo "use SDF_LIBRARY_PATH_X86_64 from environment: $x86_64_sdk_library_dir"
fi

if [ -z "${SDF_LIBRARY_PATH_AARCH64:-}" ]; then
    mkdir -p "$aarch64_sdk_library_dir"
else
    echo "use SDF_LIBRARY_PATH_AARCH64 from environment: $aarch64_sdk_library_dir"
fi

if [ -n "${SDF_EXECUTABLE_X86_64:-}" ]; then
    echo "use SDF_EXECUTABLE_X86_64 from environment: $SDF_EXECUTABLE_X86_64"
fi

if [ -n "${SDF_EXECUTABLE_AARCH64:-}" ]; then
    echo "use SDF_EXECUTABLE_AARCH64 from environment: $SDF_EXECUTABLE_AARCH64"
fi

host_arch=$(uname -m)
case "$host_arch" in
    x86_64)
        x86_64_compiler=${SDF_EXECUTABLE_X86_64:-gcc}
        aarch64_compiler=${SDF_EXECUTABLE_AARCH64:-}

        # Download the aarch64 cross compiler only when one was not configured.
        if [ -z "$aarch64_compiler" ]; then
            if [ ! -f "$toolchain_cache_dir/${aarch64_toolchain_url##*/}" ]; then
                echo "begin to download toolchain: ${aarch64_toolchain_url##*/}......"
                wget -c -P "$toolchain_cache_dir" "$aarch64_toolchain_url"
            fi

            if [ ! -f "$toolchain_cache_dir/${aarch64_toolchain_url##*/}" ]; then
                echo "ERROR: Failed to download toolchain from ${aarch64_toolchain_url}"
                exit 1
            fi

            if [ ! -d "$toolchain_cache_dir/$(basename "$aarch64_toolchain_url" .tar.xz)" ]; then
                echo "begin to tar -xf ${aarch64_toolchain_url##*/}......"
                tar -xf "$toolchain_cache_dir/${aarch64_toolchain_url##*/}" -C "$toolchain_cache_dir"
            fi
            aarch64_compiler=$toolchain_cache_dir/$(basename "$aarch64_toolchain_url" .tar.xz)/bin/aarch64-linux-gnu-gcc
        fi

        # Generate an SDK stub only when no library path was configured for
        # the corresponding target architecture.
        if [ -z "${SDF_LIBRARY_PATH_X86_64:-}" ]; then
            "$x86_64_compiler" -fPIC -shared -o "$sdk_stub_output_file" \
                "$sdk_stub_source_file" -I "$sdk_header_dir"
            mv -f "$sdk_stub_output_file" "$x86_64_sdk_library_dir"
        fi

        if [ -z "${SDF_LIBRARY_PATH_AARCH64:-}" ]; then
            "$aarch64_compiler" -fPIC -shared -o "$sdk_stub_output_file" \
                "$sdk_stub_source_file" -I "$sdk_header_dir"
            mv -f "$sdk_stub_output_file" "$aarch64_sdk_library_dir"
        fi
        ;;
    aarch64|arm64)
        # Zig publishes an aarch64-hosted compiler and includes the headers and
        # libraries needed to cross-compile and link an x86_64 GNU/Linux .so.
        # Use a GCC-compatible wrapper because native-maven-plugin accepts only
        # an executable path, not a command followed by arguments.
        x86_64_compiler=${SDF_EXECUTABLE_X86_64:-}
        aarch64_compiler=${SDF_EXECUTABLE_AARCH64:-gcc}

        if [ -z "$x86_64_compiler" ]; then
            if [ ! -f "$toolchain_cache_dir/${x86_64_toolchain_url##*/}" ]; then
                echo "begin to download x86_64 cross toolchain: ${x86_64_toolchain_url##*/}......"
                wget -c -P "$toolchain_cache_dir" "$x86_64_toolchain_url"
            fi

            if [ ! -f "$toolchain_cache_dir/${x86_64_toolchain_url##*/}" ]; then
                echo "ERROR: Failed to download x86_64 cross toolchain from ${x86_64_toolchain_url}"
                exit 1
            fi

            if [ ! -d "$toolchain_cache_dir/$(basename "$x86_64_toolchain_url" .tgz | sed 's/zig-linux-arm64-/zig-aarch64-linux-/')" ]; then
                echo "begin to tar -xf ${x86_64_toolchain_url##*/}......"
                tar -xOzf "$toolchain_cache_dir/${x86_64_toolchain_url##*/}" package/zig.tar.xz \
                    | tar -xJf - -C "$toolchain_cache_dir"
            fi

            zig_compiler=$toolchain_cache_dir/$(basename "$x86_64_toolchain_url" .tgz \
                | sed 's/zig-linux-arm64-/zig-aarch64-linux-/')/zig
            x86_64_compiler=$build_env_dir/x86_64-linux-gnu-gcc
            cat > "$x86_64_compiler" << EOF
#!/bin/sh
export ZIG_GLOBAL_CACHE_DIR="$toolchain_cache_dir/zig-global-cache"
compile_only=false
for argument do
    case "\$argument" in
        -fno-aggressive-loop-optimizations|-fno-gnu-unique) ;;
        -c)
            compile_only=true
            set -- "\$@" "\$argument"
            ;;
        *) set -- "\$@" "\$argument" ;;
    esac
    shift
done
# zig cc uses Clang-compatible flags. Use ReleaseFast-equivalent optimization
# for C sources while preserving the existing debug and symbol information.
if [ "\$compile_only" = true ]; then
    exec "$zig_compiler" cc -target x86_64-linux-gnu "\$@" -O3 -DNDEBUG
fi
exec "$zig_compiler" cc -target x86_64-linux-gnu "\$@" -O3 -DNDEBUG
EOF
            chmod +x "$x86_64_compiler"
        fi

        if [ -z "${SDF_LIBRARY_PATH_X86_64:-}" ]; then
            "$x86_64_compiler" -fPIC -shared -o "$sdk_stub_output_file" \
                "$sdk_stub_source_file" -I "$sdk_header_dir"
            mv -f "$sdk_stub_output_file" "$x86_64_sdk_library_dir"
        fi

        if [ -z "${SDF_LIBRARY_PATH_AARCH64:-}" ]; then
            "$aarch64_compiler" -fPIC -shared -o "$sdk_stub_output_file" \
                "$sdk_stub_source_file" -I "$sdk_header_dir"
            mv -f "$sdk_stub_output_file" "$aarch64_sdk_library_dir"
        fi
        ;;
    *)
        echo "ERROR: unsupported build architecture: $host_arch"
        exit 1
        ;;
esac

# create env properties for maven install
echo "begin to create env properties...."
cat > "$build_env_dir/env.properties" << EOF
SDF_EXECUTABLE_X86_64=$x86_64_compiler
SDF_EXECUTABLE_AARCH64=$aarch64_compiler
SDF_LIBRARY_PATH_X86_64=$x86_64_sdk_library_dir
SDF_LIBRARY_PATH_AARCH64=$aarch64_sdk_library_dir
EOF

echo "========== prepare env finished =========="
