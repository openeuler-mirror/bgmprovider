/*
 * Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.gm.javax.net.ssl.templates;

import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.cert.X509Certificate;

import static org.openeuler.gm.TestUtils.*;

/**
 * A template to use "www.example.com" as the server name.  The caller should
 *  set a virtual hosts file with System Property, "jdk.net.hosts.file". This
 *  class will map the loopback address to "www.example.com", and write to
 *  the specified hosts file.
 *
 * Commands used:
 * ############# CA #############
 * # Generate CA key
 * keytool -genkey -keyalg SM2 -sigalg SM3withSM2  -keysize 256 -ext KeyUsage=DigitalSignature,nonRepudiation,keyCertSign,crlSign -ext BasicConstraints=CA:true -keystore server-rootca.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias server-rootca -dname "CN=server-rootca" -validity 3650 -storetype pkcs12
 *
 * # Export CA certificate
 * keytool -exportcert -keystore server-rootca.keystore -alias server-rootca -file server-rootca.crt -storepass 12345678 -trustcacerts -storetype pkcs12
 *
 * # Import the CA certificate into $JAVA_HOME/jre/lib/security/cacerts
 * keytool -delete -alias server-rootca -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit
 * keytool -import -alias server-rootca -file server-rootca.crt -keystore  $JAVA_HOME/jre/lib/security/cacerts -storepass changeit -trustcacerts -noprompt
 * keytool -importcert -file server-rootca.crt -alias server-rootca -keystore server.truststore -storepass 12345678 -trustcacerts -noprompt -storetype pkcs12
 *
 * ############# SM2 Enc #############
 * # Generate SM2 encryption key
 * keytool -genkey -keyalg SM2 -sigalg SM3withSM2  -keysize 256 -ext KeyUsage=keyEncipherment,dataEncipherment,keyAgreement  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1,dns:www.example.com,ip:127.0.0.1  -keystore server.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias server-sm2-enc -dname "CN=server/sm2/enc" -validity 3650 -storetype pkcs12
 *
 * # SM2 encryption certificate request
 * keytool -certreq -alias server-sm2-enc -sigAlg SM3withSM2 -keystore server.keystore -file server-sm2-enc.csr -storepass 12345678 -storetype pkcs12
 *
 * # Issue SM2 encryption certificate
 * keytool -gencert -ext KeyUsage=keyEncipherment,dataEncipherment,keyAgreement  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1,dns:www.example.com,ip:127.0.0.1   -sigalg SM3withSM2  -alias server-rootca -keystore server-rootca.keystore -infile server-sm2-enc.csr -outfile server-sm2-enc.crt -storepass 12345678 -storetype pkcs12
 *
 * # Import SM2 encryption certificate to keystore to generate certificate chain
 * keytool -import -alias server-sm2-enc -file server-sm2-enc.crt -keystore server.keystore -trustcacerts -storepass 12345678 -trustcacerts -storetype pkcs12
 *
 * # Import SM2 encryption key to server-sm2-enc.keystore
 * keytool -importkeystore -srckeystore server.keystore -srcalias server-sm2-enc -destalias server-sm2-enc -destkeystore server-sm2-enc.keystore -srckeypass 12345678 -destkeypass 12345678 -srcstorepass 12345678 -deststorepass 12345678 -deststoretype pkcs12
 *
 * ############# SM2 Sig #############
 *
 * # Generate SM2 signature key
 * keytool -genkey -keyalg SM2 -sigalg SM3withSM2  -keysize 256 -ext KeyUsage=digitalSignature  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1,dns:www.example.com,ip:127.0.0.1   -keystore server.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias server-sm2-sig -dname "CN=server/sm2/sig" -validity 3650  -storetype pkcs12
 *
 * # SM2 signature certificate request
 * keytool -certreq -alias server-sm2-sig -sigAlg SM3withSM2 -keystore server.keystore -file server-sm2-sig.csr -storepass 12345678  -storetype pkcs12
 *
 * # Issue SM2 signature certificate
 * keytool -gencert -ext KeyUsage=digitalSignature  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1,dns:www.example.com,ip:127.0.0.1    -sigalg SM3withSM2 -alias server-rootca -keystore server-rootca.keystore -infile server-sm2-sig.csr -outfile server-sm2-sig.crt -storepass 12345678  -storetype pkcs12
 *
 * # Import SM2 signature certificate to keystore to generate certificate chain
 * keytool -import -alias server-sm2-sig -file server-sm2-sig.crt -keystore server.keystore -trustcacerts -storepass 12345678 -trustcacerts -storetype pkcs12
 *
 * # Import SM2 signature key to server-sm2-sig.keystore
 * keytool -importkeystore -srckeystore server.keystore -srcalias server-sm2-sig -destalias server-sm2-sig -destkeystore server-sm2-sig.keystore -srckeypass 12345678 -destkeypass 12345678 -srcstorepass 12345678 -deststorepass 12345678 -deststoretype pkcs12
 *
 */

public class SSLExampleCert {

    private static final String BGM_BASE_PACKAGE = "org.openeuler.sun.security.ssl";
    private static final String BGM_DEFAULTMANAGERSHOLDER_CLASS_NAME = BGM_BASE_PACKAGE +
            ".SSLContextImpl$DefaultManagersHolder";
    private static final String SERVER_SIG_KEYSTORE = "gm/javax/net/ssl/ServerName/server-sm2-sig.keystore";
    private static final String SERVER_ENC_KEYSTORE = "gm/javax/net/ssl/ServerName/server-sm2-enc.keystore";
    private static final String PASSPHRASE = "12345678";
    private static final String KEYSTORE_TYPE = "PKCS12";


    /**
     *     Set "www.example.com" to loopback address.
     *     Just For JDK11+
     */
    static {
        String hostsFileName = System.getProperty("jdk.net.hosts.file");
        String loopbackHostname =
                InetAddress.getLoopbackAddress().getHostAddress() +
                        " " + "www.example.com    www.example.com.\n";
        try (FileWriter writer= new FileWriter(hostsFileName, false)) {
            writer.write(loopbackHostname);
        } catch (IOException ioe) {
            // ignore
        }
    }

    public static SSLContext createServerSSLContext() throws Exception {
        String[] keyPaths =getPaths(new String[]{
                SERVER_SIG_KEYSTORE,
                SERVER_ENC_KEYSTORE
        });

        System.setProperty("javax.net.ssl.keyStore", arrayToString(keyPaths));
        System.setProperty("javax.net.ssl.keyStoreType", KEYSTORE_TYPE);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSPHRASE);

        SSLContext sslContext = SSLContext.getInstance("GMTLS");
        KeyManager[] keyManagers = getKeyManagers();

        sslContext.init(keyManagers, null, new java.security.SecureRandom());
        return sslContext;
    }

    private static KeyManager[] getKeyManagers() throws Exception {
        Class<?> clazz = Class.forName(BGM_DEFAULTMANAGERSHOLDER_CLASS_NAME);
        Method method = clazz.getDeclaredMethod("getKeyManagers");
        method.setAccessible(true);
        return (KeyManager[]) method.invoke(null);
    }

    public static SSLContext createClientSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("GMTLS");

        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        return sslContext;
    }
}
