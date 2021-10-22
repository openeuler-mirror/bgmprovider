# bgmprovider

#### Description
BGMProvider aims to provide a GMTLS JAVA implementation.

#### Software Architecture
BGMProvider is another Java Cryptography Architecture(JCA) Provider, 
including a JCE Provider and a JSSE Provider.

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

#### Contribution
code contribution is welcome!
1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request
