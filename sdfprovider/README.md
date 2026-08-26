# SDFProvider
## build && package && install
1.Configure environment variables

Here we take the `x86_64` platform as an example to build the source code.
```
export LIBRARY_PATH="/home/user/workspace/v1.1.7_v2/lib/x86_64"
```
or
```
export SDF_EXECUTABLE_X86_64="gcc"
export SDF_EXECUTABLE_AARCH64="${SDF_EXECUTABLE_X86_64}"

export SDF_LIBRARY_PATH_X86_64="/usr/lib64/cryptocard/x86_64"
export SDF_LIBRARY_PATH_AARCH64="/usr/lib64/cryptocard/aarch64"
```

2.Build package

```
mvn -Dmaven.test.skip=true clean package
```

3.Run tests

- configure environment variables
```
export LD_LIBRARY_PATH="/usr/lib64/cryptocard"
```
- run test
```
mvn clean test
```

## Cross-compilation

One Maven build produces native libraries for both supported Linux architectures, regardless of whether the
build host is `x86_64` or `aarch64`/`arm64`:

- `target/libsdfcrypto_linux_x86_64.so`
- `target/libsdfcrypto_linux_aarch64.so`

Both libraries are also packaged under `META-INF/native/` in the generated JAR.

### Prerequisites

Install a JDK, Maven, a native GCC compiler for the host architecture, `wget`, and `tar`. The first build also
requires network access if a cross compiler is not configured explicitly. Downloaded toolchains and Zig's global
cache are stored under `/tmp` and reused by later builds.

### Build on x86_64

Run:

```shell
mvn -Dmaven.test.skip=true clean package
```

The build uses the host `gcc` for the x86_64 library. If `SDF_EXECUTABLE_AARCH64` is not set,
`build/pre-env.sh` downloads the Linaro `aarch64-linux-gnu-gcc` toolchain automatically and uses it for the
aarch64 library.

To use compilers already installed on the system:

```shell
export SDF_EXECUTABLE_X86_64=gcc
export SDF_EXECUTABLE_AARCH64=aarch64-linux-gnu-gcc
mvn -Dmaven.test.skip=true clean package
```

### Build on aarch64

Run the same command:

```shell
mvn -Dmaven.test.skip=true clean package
```

The build uses the host `gcc` for the aarch64 library. If `SDF_EXECUTABLE_X86_64` is not set,
`build/pre-env.sh` downloads the aarch64-hosted Zig toolchain from the npmmirror CDN and creates a GCC-compatible
wrapper for the x86_64 target. Zig compiles the C sources with ReleaseFast-equivalent optimization while retaining
debug and symbol information.

To use compilers already installed on the system and skip the Zig download:

```shell
export SDF_EXECUTABLE_AARCH64=gcc
export SDF_EXECUTABLE_X86_64=x86_64-linux-gnu-gcc
mvn -Dmaven.test.skip=true clean package
```

The compiler paths may be absolute paths or executable names available through `PATH`.

### Verify the native libraries

```shell
file target/libsdfcrypto_linux_x86_64.so \
     target/libsdfcrypto_linux_aarch64.so

unzip -l target/sdfprovider-2.0.4.jar | grep META-INF/native
```

The `file` output should report `x86-64` for the first library and `ARM aarch64` for the second.

## test

Taking JDK8 as an example, if you wan t to use JDK's keytool tool to generate a public and private key pair, you need to copy the `common-x.jar` and `sdfprovider-x.jar` files to the `jre/lib/ext` directory, then configure the `jre/lib/security` file and set `org.openeuler.sdf.provider.SDFProvider` priority to 1.

```
security.provider.1=org.openeuler.sdf.provider.SDFProvider
security.provider.2=sun.security.provider.Sun
security.provider.3=sun.security.rsa.SunRsaSign
security.provider.4=sun.security.ec.SunEC
security.provider.5=com.sun.net.ssl.internal.ssl.Provider
security.provider.6=com.sun.crypto.provider.SunJCE
security.provider.7=sun.security.jgss.SunProvider
security.provider.8=com.sun.security.sasl.Provider
security.provider.9=org.jcp.xml.dsig.internal.dom.XMLDSigRI
security.provider.10=sun.security.smartcardio.SunPCSC
```

- generate ssl keystore and truststore

```
cd sdfprovider/src/test/resources/gmtls
bash generate_gmtls_key.sh
```

- generate keystore for SDFKeyStoreTest.java

```
cd sdfprovider/src/test/resources
bash generate_diff_key.sh
```
