# bgmprovider

#### 介绍
BGMProvider目标是提供一个完整的GMTLS JAVA实现。

#### 软件架构
BGMProvider 基于 Java Cryptography Architecture(JCA) 框架，
提供一个JCE provider 和 JSSE provider。

#### 安装教程

1.  拷贝 bgmprovider-xxxx-jar-with-dependencies.jar文件至 path_to_jre/lib/ext
2.  修改path_to_jre/lib/security/java.security文件, 添加BGMProvider。
```
security.provider.1=org.openeuler.BGMProvider
security.provider.2=sun.security.provider.Sun
security.provider.3=sun.security.rsa.SunRsaSign
security.provider.4=sun.security.ec.SunEC
security.provider.5=com.sun.net.ssl.internal.ssl.Provider
```

#### 参与贡献
欢迎所有人提交代码
1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request

