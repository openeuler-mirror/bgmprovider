# bgmprovider

#### Description
BGMProvider aims to provide a GMTLS JAVA implementation.

#### Software Architecture
BGMProvider is another Java Cryptography Architecture(JCA) Provider, 
including a JCE Provider and a JSSE Provider.

#### Build
+ Requires JDK: JDK8u302+
+ To check out and build bgmprovider, issue the following commands:
```sh
$ git clone https://gitee.com/openeuler/bgmprovider.git
$ cd bgmprovider
$ mvn install
```

#### Installation
1.  copy bgmprovider-xxxx-jar-with-dependencies.jar to path_to_jre/lib/ext
2.  edit path_to_jre/lib/security/java.security, add BGMProvider.
```
security.provider.1=org.openeuler.BGMProvider
security.provider.2=sun.security.provider.Sun
security.provider.3=sun.security.rsa.SunRsaSign
security.provider.4=sun.security.ec.SunEC
security.provider.5=com.sun.net.ssl.internal.ssl.Provider
```
3. copy tomcat-adaptor-xxxx.jar to path_to_tomcat/lib if used in tomcat.

#### Runtime Requires
+ JDK: 8u302+
+ Tomcat: 8.5.2 and above, 9.0.1 and above, 10.0.0 and above

#### Configuration
+ enable tls1.2+GMCipherSuite: -Dt12WithGMCipherSuite=true/false
+ disable some algorithms in BGMProvider: -Dbgmprovider.conf=path_to_file/filename.conf,
the format is as follows:
```
jce.sm2=false
jce.sm3=false
...
jsse.keyManagerFactory=false
...
```
The currently supported configurations are: jce.sm2, jce.sm3, jce.sm4, jce.hmacSM3, jce.signatureSM2withSM2, jce.keypairGenerator,
jce.algorithmParameters, jce.keyStore, jsse.keyManagerFactory, jsse.trustManagerFactory, jsse.keyGenerator,
jsse.sslContext

#### Contribution
code contribution is welcome!
1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request

#### LICENSE
BGMProvider is licensed under GPLv2 with Classpath Exception, see [LICENSE](https://gitee.com/openeuler/bgmprovider/blob/master/LICENSE)
