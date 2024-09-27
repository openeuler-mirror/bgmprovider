/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
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
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler.sdf.jsse.util;

import org.junit.Assert;
import org.openeuler.sdf.commons.util.SDFTestUtil;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

import static org.openeuler.sdf.commons.constant.SDFTestConstant.CLASSPATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.CLIENT_CLASS;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.ENC_CLIENT_KEYSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.ENC_CLIENT_TRUSTSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.ENC_SERVER_KEYSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.ENC_SERVER_TRUSTSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.JAVA_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.PLAIN_CLIENT_KEYSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.PLAIN_CLIENT_TRUSTSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.PLAIN_SERVER_KEYSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.PLAIN_SERVER_TRUSTSTORE_PATH;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.SERVER_CLASS;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.STORE_PASSWORD;
import static org.openeuler.sdf.commons.constant.SDFTestConstant.STORE_TYPE;

public class SDFGMTLTestUtil {
    public static final int SERVER_PORT = 29527;

    private static SSLContext getSSLContext(String keyStorePath, String keyStoreType, String keyStorePassword,
                                           String trustStorePath, String trustStoreType, String trustStorePassword)
            throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, keyStoreType, keyStorePassword);
        KeyManager[] keyManagers = getKeyManagers(keyStore, keyStorePassword);
        KeyStore trustStore = getKeyStore(trustStorePath, trustStoreType, trustStorePassword);
        TrustManager[] trustManagers = getTrustManagers(trustStore);
        SSLContext sslContext = SSLContext.getInstance("GMTLS");
        sslContext.init(keyManagers, trustManagers, null);
        return sslContext;
    }

    private static KeyStore getKeyStore(String keyStorePath, String keyStoreType, String keyStorePassword)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        try (InputStream inputStream = Files.newInputStream(Paths.get(keyStorePath))) {
            keyStore.load(inputStream, keyStorePassword.toCharArray());
        }
        return keyStore;
    }

    private static KeyManager[] getKeyManagers(KeyStore keyStore, String keyStorePassword) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] getTrustManagers(KeyStore keyStore) throws Exception {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    public static String getErrorMessage(Process process) throws Exception {
        return getMessage(process.getErrorStream());
    }
    public static String getLogMessage(Process process) throws Exception {
        return getMessage(process.getInputStream());
    }


    private static String getMessage(InputStream inputStream) throws Exception {
        int len = inputStream.available();
        if (len == 0) {
            return null;
        }
        byte[] bytes = new byte[len];
        inputStream.read(bytes);
        return new String(bytes);
    }


    private static String getKeyStorePath(boolean serverUseEnc, boolean clientUseEnc, boolean isServer) {
        String keyStorePath;
        if (isServer) {
            keyStorePath = serverUseEnc ? ENC_SERVER_KEYSTORE_PATH : PLAIN_SERVER_KEYSTORE_PATH;
        } else {
            keyStorePath = clientUseEnc ? ENC_CLIENT_KEYSTORE_PATH : PLAIN_CLIENT_KEYSTORE_PATH;
        }
        return keyStorePath;
    }

    private static String getTrustStorePath(boolean serverUseEnc, boolean clientUseEnc, boolean isServer) {
        String keyStorePath;
        if (isServer) {
            keyStorePath = clientUseEnc ? ENC_CLIENT_TRUSTSTORE_PATH : PLAIN_CLIENT_TRUSTSTORE_PATH;
        } else {
            keyStorePath = serverUseEnc ? ENC_SERVER_TRUSTSTORE_PATH : PLAIN_SERVER_TRUSTSTORE_PATH;
        }
        return keyStorePath;
    }

    private static String getJavaArgs(boolean serverUseEnc, boolean clientUseEnc, boolean isServer) {
        String args = String.format(
                "-Djavax.net.ssl.keyStore=%s " +
                        "-Djavax.net.ssl.keyStoreType=%s " +
                        "-Djavax.net.ssl.keyStorePassword=%s " +
                        "-Djavax.net.ssl.trustStore=%s " +
                        "-Djavax.net.ssl.trustStoreType=%s " +
                        "-Djavax.net.ssl.trustStorePassword=%s ",
                getKeyStorePath(serverUseEnc,clientUseEnc,isServer),
                STORE_TYPE,
                STORE_PASSWORD,
                getTrustStorePath(serverUseEnc,clientUseEnc,isServer),
                STORE_TYPE,
                STORE_PASSWORD);
        if ((serverUseEnc && isServer) | (clientUseEnc && !isServer)) {
            args = String.format("%s " +
                            "-Dsdf.defaultKEKId=%s " +
                            "-Dsdf.defaultRegionId=%s " +
                            "-Dsdf.defaultCdpId=%s",
                    args,
                    new String(SDFTestUtil.getTestKekId()),
                    new String(SDFTestUtil.getTestRegionId()),
                    new String(SDFTestUtil.getTestCdpId()));
        }
        return args;
    }

    private static String getServerJavaArgs(boolean serverUseEnc, boolean clientUseEnc) {
        return getJavaArgs(serverUseEnc, clientUseEnc, true);
    }

    private static String getCommandArgs(boolean useEncMode, int serverPort) {
        return useEncMode + " " + serverPort;
    }

    public static String getServerCommand(boolean serverUseEnc, boolean clientUseEnc, int serverPort) {
        String javaArgs = getServerJavaArgs(serverUseEnc, clientUseEnc);
        System.out.println("javaArgs: " + javaArgs);
        String commandArgs = getCommandArgs(serverUseEnc , serverPort);
        return String.format("%s %s -cp %s %s %s", JAVA_PATH, javaArgs, CLASSPATH, SERVER_CLASS, commandArgs);
    }

    public static String getClientCommand(boolean serverUseEnc, boolean clientUseEnc, int serverPort,
                                           String protocols, String cipherSuites) {
        String javaArgs = getClientJavaArgs(serverUseEnc, clientUseEnc, protocols, cipherSuites);
        System.out.println("javaArgs: " + javaArgs);
        String commandArgs = getCommandArgs(clientUseEnc, serverPort);
        return String.format("%s %s -cp %s %s %s", JAVA_PATH, javaArgs, CLASSPATH, CLIENT_CLASS, commandArgs);
    }

    private static String getClientJavaArgs(boolean serverUseEnc, boolean clientUseEnc, String protocols,
                                            String cipherSuites) {
        String javaArgs = getJavaArgs(serverUseEnc, clientUseEnc, false);
        if (protocols != null) {
            javaArgs = String.format("%s -Djdk.tls.client.protocols=%s ", javaArgs, protocols);
        }
        if (cipherSuites != null) {
            javaArgs = String.format("%s -Djdk.tls.client.cipherSuites=%s ", javaArgs, cipherSuites);
        }
        return javaArgs;
    }

    private static void test(String serverCommand, String clientCommand) throws Exception {
        Process serverProcess = Runtime.getRuntime().exec(serverCommand);
        Thread.sleep(1000L);
        Process clientProcess = Runtime.getRuntime().exec(clientCommand);

        clientProcess.waitFor();
        String clientErrorMessage = getErrorMessage(clientProcess);
        System.out.println("clientErrorMessage :" +clientErrorMessage);
        String clientLogMessage = getLogMessage(clientProcess);
        System.out.println("clientLogMessage :" +clientLogMessage);
        serverProcess.waitFor();

        String serverErrorMessage = getErrorMessage(serverProcess);
        System.out.println("serverErrorMessage :" + serverErrorMessage);

        String serverLogMessage = getLogMessage(serverProcess);
        System.out.println("serverLogMessage :" +serverLogMessage);


        Assert.assertEquals(0, clientProcess.exitValue());
        Assert.assertEquals(0, serverProcess.exitValue());

        serverProcess.destroy();
        clientProcess.destroy();
    }

    public static void setServerSysProps(boolean serverUseEnc, boolean clientUseEnc) {
        String keyStorePath = getKeyStorePath(serverUseEnc, clientUseEnc, true);
        String trustStorePath = getTrustStorePath(serverUseEnc, clientUseEnc, true);
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStorePassword", "12345678");
        System.setProperty("javax.net.ssl.trustStore",trustStorePath);
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStorePassword", "12345678");

        if (serverUseEnc) {
            SDFTestUtil.setKEKInfoSysPros();
        }
    }
}
