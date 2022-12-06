/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.gm;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import sun.security.action.GetPropertyAction;

import javax.net.ssl.*;
import java.io.*;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;

import java.util.*;

import static org.openeuler.gm.TestUtils.*;

public class TrustStoreManagerTest extends BaseTest {

    private static final String fileSep = File.separator;
    private static final String defaultStorePath =
            GetPropertyAction.privilegedGetProperty("java.home") +
                    fileSep + "lib" + fileSep + "security";
    private static final String defaultStore =
            defaultStorePath + fileSep + "cacerts";

    private static final String PASSWD = "12345678";

    private static final String SUN_BASE_PACKAGE = "sun.security.ssl";
    private static final String BGM_BASE_PACKAGE = "org.openeuler.sun.security.ssl";

    private static final String SUN_TRUSTSTOREMANAGER_CLASS_NAME = SUN_BASE_PACKAGE + ".TrustStoreManager";

    private static final String BGM_TRUSTSTOREMANAGER_CLASS_NAME = BGM_BASE_PACKAGE + ".TrustStoreManager";

    private static final String PKCS12 = "PKCS12";

    private static final String JKS = "JKS";

    private static final String NONE = "NONE";

    private static final String BGMJSSEPROVIDER = "BGMJSSEProvider";

    private static final String SUN_DEFAULTMANAGERSHOLDER_CLASS_NAME = SUN_BASE_PACKAGE +
            ".SSLContextImpl$DefaultManagersHolder";
    private static final String BGM_DEFAULTMANAGERSHOLDER_CLASS_NAME = BGM_BASE_PACKAGE +
            ".SSLContextImpl$DefaultManagersHolder";

    private static final int SERVER_PORT = 0;

    @BeforeClass
    public static void beforeClass() {
        if (debug) {
            System.setProperty("javax.net.debug", "all");
        }
    }

    @Test
    public void testDefaultProps() throws Exception {
        test(defaultStore, JKS);
    }

    @Test
    public void testOneTrustStore() throws Exception {
        String expectedPath = getPath("server-rsa.truststore");
        System.setProperty("javax.net.ssl.trustStore", Objects.requireNonNull(expectedPath));
        System.setProperty("javax.net.ssl.trustStoreType", PKCS12);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWD);
        try {
            test(expectedPath, PKCS12, PASSWD);
        } finally {
            System.getProperties().remove("javax.net.ssl.trustStore");
            System.getProperties().remove("javax.net.ssl.trustStoreType");
            System.getProperties().remove("javax.net.ssl.trustStorePassword");
        }
    }

    @Test
    public void testMultipleTrustStore() throws Exception {
        String[] expectedPaths = getPaths(new String[]{
                "server-rsa.truststore",
                "server-ec.truststore",
                "server-sm2-sig.truststore",
                "server-sm2-enc.truststore"
        });
        String expectedType = PKCS12;
        System.setProperty("javax.net.ssl.trustStore", arrayToString(expectedPaths));
        System.setProperty("javax.net.ssl.trustStoreType", expectedType);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWD);
        try {
            test(expectedPaths, expectedType, PASSWD);
        } finally {
            System.getProperties().remove("javax.net.ssl.trustStore");
            System.getProperties().remove("javax.net.ssl.trustStoreType");
            System.getProperties().remove("javax.net.ssl.trustStorePassword");
        }
    }

    @Test
    public void testOnlyNoneTrustStore() throws Exception {
        String expectedPath = NONE;
        String expectedType = JKS;
        System.setProperty("javax.net.ssl.trustStore", NONE);
        try {
            List<StoreInfo> storeInfos = test(expectedPath, expectedType);
            StoreInfo expectedInfo = storeInfos.get(0);
            // Test whether the keystore is empty.
            Assert.assertEquals(0, expectedInfo.certs.size());
            Assert.assertEquals(0, expectedInfo.credentials.size());
        } finally {
            System.getProperties().remove("javax.net.ssl.trustStore");
        }
    }

    @Test
    public void testSetEmptyTrustStoreType() {
        System.setProperty("javax.net.ssl.trustStoreType", "");
        try {
            testException();
        } finally {
            System.getProperties().remove("javax.net.ssl.trustStoreType");
        }
    }

    @Test
    public void testOnlySetTrustStorePassword() {
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWD);
        try {
            testException();
        } finally {
            System.getProperties().remove("javax.net.ssl.trustStorePassword");
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidTrustStoreType() throws Throwable {
        testIllegalArgumentException("javax.net.ssl.trustStoreType", "PKCS12,JKS");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidTrustStoreProvider() throws Throwable {
        testIllegalArgumentException("javax.net.ssl.trustStoreProvider", "SunJSSE,BGMJSSEProvider");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidTrustStorePassword() throws Throwable {
        testIllegalArgumentException("javax.net.ssl.trustStorePassword", "12345678,12345678");
    }

    public TLSResult testTLS(int serverPort, String[] storeFileNames, String provider) {
        return testTLS(serverPort, storeFileNames, provider, null, null);
    }

    public TLSResult testTLS(int serverPort, String[] storeFileNames, String provider,
                             String[] clientEnabledProtocols, String[] enabledCipherSuites) {
        Server server = new Server(serverPort, provider);
        new Thread(server::run).start();
        while (!server.isStarted) {
            try {
                Thread.sleep(10L);
            } catch (InterruptedException e) {
                System.err.println(e.getMessage());
            }
        }

        Client client = new Client(server.serverPort, storeFileNames, provider);
        if (clientEnabledProtocols != null) {
            client.setEnabledProtocols(clientEnabledProtocols);
        }
        if (enabledCipherSuites != null) {
            client.setEnabledCipherSuites(enabledCipherSuites);
        }

        client.run();
        return new TLSResult(server, client);
    }

    @Test
    public void testAllCerts() {
        String[] storeFileNames = new String[]{
                "server-rsa.truststore",
                "server-ec.truststore",
                "server-sm2-sig.truststore",
                "server-sm2-enc.truststore"
        };
        TLSResult tlsResult = testTLS(SERVER_PORT, storeFileNames, null);
        tlsResult.assertSuccess();
    }

    @Test
    public void testECCert() {
        String[] storeFileNames = new String[]{
                "server-ec.truststore"
        };
        TLSResult tlsResult = testTLS(SERVER_PORT, storeFileNames, null);
        String actualMessage = "PKIX path building failed: " +
                "sun.security.provider.certpath.SunCertPathBuilderException:" +
                " unable to find valid certification path to requested target";
        tlsResult.assertClientException(actualMessage);

        tlsResult = testTLS(SERVER_PORT, storeFileNames, null, new String[]{"TLSv1.2"}, null);
        tlsResult.assertSuccess();
    }

    @Test
    public void testRSACert() {
        String[] storeFileNames = new String[]{
                "server-rsa.truststore"
        };
        TLSResult tlsResult = testTLS(SERVER_PORT, storeFileNames, null);
        String actualMessage = "PKIX path building failed: " +
                "sun.security.provider.certpath.SunCertPathBuilderException:" +
                " unable to find valid certification path to requested target";
        tlsResult.assertClientException(actualMessage);

        tlsResult = testTLS(SERVER_PORT, storeFileNames, null, new String[]{"TLSv1.2"},
                new String[]{"TLS_RSA_WITH_AES_256_GCM_SHA384"});
        tlsResult.assertSuccess();
    }

    private static class TLSResult {
        private Server server;
        private Client client;

        public TLSResult(Server server, Client client) {
            this.server = server;
            this.client = client;
        }

        public void assertSuccess() {
            Assert.assertNull(server.exception);
            Assert.assertNull(client.exception);
        }

        public void assertClientException(String expected) {
            String actual = this.client.exception != null ? this.client.exception.getMessage() : "";
            Assert.assertEquals(expected, actual);
        }
    }

    /*
     * Server
     */
    private static class Server {
        private volatile boolean isStarted;
        private volatile boolean isFinished;
        private volatile Exception exception;
        private int serverPort;
        private final String provider;

        public void setServerPort(int serverPort) {
            this.serverPort = serverPort;
        }

        public Server(int serverPort, String provider) {
            this.serverPort = serverPort;
            this.provider = provider;
        }

        public void run() {
            startServer(this.serverPort, this.provider);
        }

        private void startServer(int port, String provider) {
            ServerSocket serverSocket = null;
            try {
                SSLContext sslContext;
                if (provider != null) {
                    sslContext = SSLContext.getInstance("TLS", provider);
                } else {
                    sslContext = SSLContext.getInstance("TLS");
                }
                KeyStore ks = loadKeyStore(getPath("server.keystore"),
                        PKCS12, PASSWD);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, PASSWD.toCharArray());
                sslContext.init(kmf.getKeyManagers(), null, null);
                SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
                serverSocket = ssf.createServerSocket(port);
                setServerPort(serverSocket.getLocalPort());
                this.isStarted = true;
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                String message = inputStream.readUTF();
                System.out.println("server receive : " + message);
            } catch (Exception e) {
                exception = e;
            } finally {
                this.isStarted = true;
                this.isFinished = true;
                if (serverSocket != null) {
                    try {
                        serverSocket.close();
                    } catch (IOException e) {
                        System.err.println(e.getMessage());
                    }
                }
            }
        }
    }

    /*
     * Client
     */
    private static class Client {
        private final int serverPort;
        private final String[] storeFileNames;
        private final String provider;
        private volatile Exception exception;

        public void setEnabledProtocols(String[] enabledProtocols) {
            this.enabledProtocols = enabledProtocols;
        }

        public void setEnabledCipherSuites(String[] enabledCipherSuites) {
            this.enabledCipherSuites = enabledCipherSuites;
        }

        private String[] enabledProtocols;
        private String[] enabledCipherSuites;

        private Client(int serverPort, String[] storeFileNames, String provider) {
            this.serverPort = serverPort;
            this.storeFileNames = storeFileNames;
            this.provider = provider;
        }

        public void run() {
            startClient(this.serverPort, this.storeFileNames, this.provider);
        }

        private void startClient(int port, String[] storeFileNames, String provider) {
            String[] expectedPaths = getPaths(storeFileNames);
            SSLSocket socket = null;
            try {
                System.setProperty("javax.net.ssl.trustStore", arrayToString(expectedPaths));
                System.setProperty("javax.net.ssl.trustStoreType", PKCS12);
                System.setProperty("javax.net.ssl.trustStorePassword", PASSWD);

                SSLContext sslContext;
                if (provider != null) {
                    sslContext = SSLContext.getInstance("TLS", provider);
                } else {
                    sslContext = SSLContext.getInstance("TLS");
                }
                TrustManager[] trustManagers = BGMJSSEPROVIDER.equals(sslContext.getProvider().getName()) ?
                        getBGMTrustManagers() : getSunTrustManagers();
                sslContext.init(null, trustManagers, null);

                SSLSocketFactory sf = sslContext.getSocketFactory();
                socket = (SSLSocket) sf.createSocket("localhost", port);
                if (enabledProtocols != null) {
                    socket.setEnabledProtocols(enabledProtocols);
                }
                if (enabledCipherSuites != null) {
                    socket.setEnabledCipherSuites(enabledCipherSuites);
                }

                DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                String message = "Hello Server";
                System.out.println("Client send : " + message);
                outputStream.writeUTF(message);
            } catch (Exception e) {
                exception = e;
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        System.err.println(e.getMessage());
                    }
                }
                try {
                    if (provider == null || BGMJSSEPROVIDER.equals(provider)) {
                        clearBGMKeyStoreRef();
                    } else {
                        clearSunKeyStoreRef();
                    }
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }
                System.getProperties().remove("javax.net.ssl.trustStore");
                System.getProperties().remove("javax.net.ssl.trustStoreType");
                System.getProperties().remove("javax.net.ssl.trustStorePassword");
            }
        }
    }

    private static TrustManager[] getBGMTrustManagers() throws Exception {
        return getTrustManagers(BGM_DEFAULTMANAGERSHOLDER_CLASS_NAME);
    }

    private static TrustManager[] getSunTrustManagers() throws Exception {
        return getTrustManagers(SUN_DEFAULTMANAGERSHOLDER_CLASS_NAME);
    }

    private static TrustManager[] getTrustManagers(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getDeclaredMethod("getTrustManagers");
        method.setAccessible(true);
        return (TrustManager[]) method.invoke(null);
    }

    private void testIllegalArgumentException(String propKey, String propValue) throws Throwable {
        String[] expectedPaths = getPaths(new String[]{
                "server-rsa.truststore",
                "server-ec.truststore",
                "server-sm2-sig.truststore",
                "server-sm2-enc.truststore"
        });
        System.setProperty("javax.net.ssl.trustStore", arrayToString(expectedPaths));
        System.setProperty(propKey, propValue);
        try {
            getActualStore();
        } catch (Exception e) {
            throw e.getCause();
        } finally {
            System.getProperties().remove("javax.net.ssl.trustStore");
            System.getProperties().remove(propKey);
        }
    }

    private void testException() {
        String expected = getExceptionMessage(SUN_TRUSTSTOREMANAGER_CLASS_NAME);
        System.err.println("expected=" + expected);
        String actual = getExceptionMessage(BGM_TRUSTSTOREMANAGER_CLASS_NAME);
        System.err.println("actual=" + actual);
        Assert.assertEquals(expected, actual);
    }

    private String getExceptionMessage(String className) {
        String message = "";
        try {
            getActualStore(className);
        } catch (Exception e) {
            message = e.getCause().getMessage();
        }
        return message;
    }

    private List<StoreInfo> test(String expectedPath, String expectedType) throws Exception {
        return test(expectedPath, expectedType, null);
    }

    private List<StoreInfo> test(String expectedPath, String expectedType, String expectedPassword)
            throws Exception {
        KeyStore expectedStore = loadKeyStore(expectedPath, expectedType, expectedPassword);
        StoreInfo expectedInfo = getStoreInfo(expectedStore, expectedPassword);
        KeyStore actualStore = getActualStore();
        StoreInfo actualInfo = getStoreInfo(actualStore, expectedPassword);
        Assert.assertEquals(expectedInfo, actualInfo);
        return Arrays.asList(expectedInfo, actualInfo);
    }

    private List<StoreInfo> test(String[] expectedPaths, String[] expectedTypes, String[] expectedPasswords)
            throws Exception {
        KeyStore[] expectedStores = loadKeyStores(expectedPaths,
                expectedTypes, expectedPasswords);
        StoreInfo expectedInfo = getStoreInfo(expectedStores, expectedPasswords);
        KeyStore actualStore = getActualStore();
        StoreInfo actualInfo = getStoreInfo(actualStore, expectedPasswords[0]);
        Assert.assertEquals(expectedInfo, actualInfo);
        return Arrays.asList(expectedInfo, actualInfo);
    }

    private List<StoreInfo> test(String[] expectedPaths, String expectedType, String expectedPassword)
            throws Exception {
        String[] expectedTypes = new String[expectedPaths.length];
        Arrays.fill(expectedTypes, expectedType);
        String[] expectedPasswords = new String[expectedPaths.length];
        Arrays.fill(expectedPasswords, expectedPassword);
        return test(expectedPaths, expectedTypes, expectedPasswords);
    }


    private List<StoreInfo> test(String[] expectedPaths, String expectedType) throws Exception {
        String[] expectedTypes = new String[expectedPaths.length];
        Arrays.fill(expectedTypes, expectedType);
        String[] expectedPasswords = new String[expectedPaths.length];
        return test(expectedPaths, expectedTypes, expectedPasswords);
    }

    private static KeyStore getActualStore() throws Exception {
        return getActualStore(BGM_TRUSTSTOREMANAGER_CLASS_NAME);
    }

    private static KeyStore getActualStore(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getDeclaredMethod("getTrustedKeyStore");
        method.setAccessible(true);
        KeyStore keyStore;
        try {
            keyStore = (KeyStore) method.invoke(null);
        } finally {
            clearBGMKeyStoreRef(clazz);
        }
        return keyStore;
    }

    @SuppressWarnings("unchecked")
    private static void clearBGMKeyStoreRef(Class<?> clazz) throws Exception {
        Field field = clazz.getDeclaredField("tam");
        field.setAccessible(true);
        Object tam = field.get(null);
        Field ksRefField = tam.getClass().getDeclaredField("ksRef");
        ksRefField.setAccessible(true);
        WeakReference<KeyStore> ksRef = (WeakReference<KeyStore>) ksRefField.get(tam);
        ksRef.clear();
    }

    private static void clearBGMKeyStoreRef() throws Exception {
        Class<?> clazz = Class.forName(BGM_TRUSTSTOREMANAGER_CLASS_NAME);
        clearBGMKeyStoreRef(clazz);
    }

    private static void clearSunKeyStoreRef() throws Exception {
        Class<?> clazz = Class.forName(SUN_TRUSTSTOREMANAGER_CLASS_NAME);
        clearBGMKeyStoreRef(clazz);
    }

}
