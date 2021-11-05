# bgmprovider

#### 介绍
BGMProvider目标是提供一个完整的GMTLS JAVA实现。

#### 软件架构
BGMProvider 基于 Java Cryptography Architecture(JCA) 框架，
提供一个JCE provider 和 JSSE provider。

#### 源码构建
+ 编译要求: JDK8u302+
执行下面命令即可：
```sh
$ git clone https://gitee.com/openeuler/bgmprovider.git
$ cd bgmprovider
$ mvn install
```

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
3. 如果在tomcat中使用，则需要将tomcat-adaptor-1.x.x.jar拷贝至$TOMCAT_HOME/lib

#### 运行要求
+ JDK: 8u302+
+ Tomcat: 8.5.2及以上，9.0.1及以上，10.0.0及以上

#### 参数
+ 支持tls1.2+国密加密套件: 通过-Dt12WithGMCipherSuite=true/false打开或关闭此功能，默认关闭
+ 不启用BGMProvider中的特定算法：通过-Dbgmprovider.conf=path_to_file/filename.conf指定配置文件，
并将特定算法的值改为false，格式如下：
```
jce.sm2=false
jce.sm3=false
...
jsse.keyManagerFactory=false
...
```
当前支持的配置有：jce.sm2, jce.sm3, jce.sm4, jce.hmacSM3, jce.signatureSM2withSM2, jce.keypairGenerator,
jce.algorithmParameters, jce.keyStore, jsse.keyManagerFactory, jsse.trustManagerFactory, jsse.keyGenerator,
jsse.sslContext

#### 参与贡献
欢迎所有人提交代码
1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request

#### LICENSE
BGMProvider使用GPLv2 with Classpath Exception, 请见[LICENSE](https://gitee.com/openeuler/bgmprovider/blob/master/LICENSE)
