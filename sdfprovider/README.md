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

## cross-compilation

Here we take the x86_64 platform to build aarch64 dynamic library at the same time as an example.

1.Download the cross-compilation toolchain

http://releases.linaro.org/components/toolchain/binaries/7.5-2019.12/aarch64-linux-gnu/

https://publishing-ie-linaro-org.s3.amazonaws.com/releases/components/toolchain/binaries/7.5-2019.12/aarch64-linux-gnu/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz

2.Configure environment variables

- Place `libswsds` and `libboundscheck` in the aarch64 and x86_64 directories

```
$ tree /usr/lib64/cryptocard
├── aarch64
│   ├── libcrypto_card_sdk.so
└── x86_64
    ├── libcrypto_card_sdk.so
```

- Configure cross-compilation toolchain environment variables
```
export TOOL_CHAINS_HOME="/home/user/toolchain/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu"
export PATH=$TOOL_CHAINS_HOME/bin:$PATH

```

- Configure environment variables required for compilation 

When cross compiling on an x86_64 machine, use `aarch64-linux-gnu-gcc` to compile and generate aarch64 so library.
```
export SDF_EXECUTABLE_X86_64="gcc"
export SDF_EXECUTABLE_AARCH64="aarch64-linux-gnu-gcc"

export SDF_LIBRARY_PATH_X86_64="/usr/lib64/cryptocard/x86_64"
export SDF_LIBRARY_PATH_AARCH64="/usr/lib64/cryptocard/aarch64"
```

- Build package

```
mvn -Dmaven.test.skip=true clean package
```
Generate two dynamic libraries `libsdfcrypto_linux_x86_64.so` and `libsdfcrypto_linux_aarch64.so`.


3.You can also use the `compiler.executable.x86_64`, `compiler.executable.aarch64` system properties to configure the 
compilation tools used,
use the `compiler.library_path.x86_64`, `compiler.library_path.aarch64` configures the dynamic library search path

```
 mvn -DskipTests -Dcompiler.executable.aarch64=aarch64-linux-gnu-gcc -Dcompiler.library_path.x86_64="/home/user/workspace/v1.1.7_v2/lib/x86_64" -Dcompiler.library_path.aarch64="/home/user/workspace/v1.1.7_v2/lib/aarch64" clean package
```

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



