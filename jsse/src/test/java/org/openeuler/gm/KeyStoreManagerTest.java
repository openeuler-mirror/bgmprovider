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

import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.openeuler.gm.TestUtils.*;

public class KeyStoreManagerTest extends BaseTest {
    private static final String PKCS12 = "PKCS12";
    private static final String PASSWD = "12345678";
    private static final String BGMJSSEPROVIDER = "BGMJSSEProvider";
    private static final String BGM_BASE_PACKAGE = "org.openeuler.sun.security.ssl";
    private static final String BGM_DEFAULTMANAGERSHOLDER_CLASS_NAME = BGM_BASE_PACKAGE +
            ".SSLContextImpl$DefaultManagersHolder";

    @BeforeClass
    public static void beforeClass() {
        if (debug) {
            System.setProperty("javax.net.debug", "all");
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKeyStoreType() throws Exception {
        System.setProperty("javax.net.ssl.keyStoreType", "JKS,PKCS12");
        try {
            KeyStoreManager.getKeyManagers();
        } finally {
            System.getProperties().remove("javax.net.ssl.keyStoreType");
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKeyStorePassword() throws Exception {
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWD + "," + PASSWD);
        try {
            KeyStoreManager.getKeyManagers();
        } finally {
            System.getProperties().remove("javax.net.ssl.keyStorePassword");
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKeyStoreProvider() throws Exception {
        System.setProperty("javax.net.ssl.keyStoreProvider", BGMJSSEPROVIDER + "," + BGMJSSEPROVIDER);
        try {
            KeyStoreManager.getKeyManagers();
        } finally {
            System.getProperties().remove("javax.net.ssl.keyStoreProvider");
        }
    }

    @Test
    public void testMultipleKeyStore() throws Exception {
        String[] expectedPaths = getPaths(new String[]{
                "server-rsa.keystore",
                "server-ec.keystore",
                "server-sm2-sig.keystore",
                "server-sm2-enc.keystore"
        });
        System.setProperty("javax.net.ssl.keyStore", arrayToString(expectedPaths));
        System.setProperty("javax.net.ssl.keyStoreType", PKCS12);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWD);

        String[] expectedTypes = new String[expectedPaths.length];
        Arrays.fill(expectedTypes, PKCS12);
        String[] expectedPasswords = new String[expectedPaths.length];
        Arrays.fill(expectedPasswords, PASSWD);

        try {
            KeyStore[] expectedKeyStores = loadKeyStores(expectedPaths, expectedTypes, expectedPasswords);
            X509ExtendedKeyManager keyManager = getKeyManager();
            test(expectedKeyStores, expectedPasswords, keyManager);
        } finally {
            System.getProperties().remove("javax.net.ssl.keyStore");
            System.getProperties().remove("javax.net.ssl.keyStoreType");
            System.getProperties().remove("javax.net.ssl.keyStorePassword");
        }
    }

    private X509ExtendedKeyManager getKeyManager() throws Exception {
        KeyManager[] keyManagers = KeyStoreManager.getKeyManagers();
        Assert.assertTrue(keyManagers.length > 0);
        return (X509ExtendedKeyManager) keyManagers[0];
    }

    private void test(KeyStore[] stores, String[] passwords, X509ExtendedKeyManager keyManager)
            throws Exception {
        Assert.assertEquals(stores.length, passwords.length);
        for (int i = 0; i < stores.length; i++) {
            test(stores[i], passwords[i], keyManager);
        }
    }

    private void test(KeyStore store, String password, X509ExtendedKeyManager keyManager)
            throws Exception {
        for (Enumeration<String> e = store.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            if (store.isKeyEntry(alias)) {
                // test certificate chain
                Certificate[] expectedCerts = store.getCertificateChain(alias);
                X509Certificate[] actualCerts = keyManager.getCertificateChain(alias);
                Assert.assertArrayEquals(expectedCerts, actualCerts);

                // test key
                if ((expectedCerts != null) && (expectedCerts.length > 0) &&
                        (expectedCerts[0] instanceof X509Certificate)) {
                    Key expectedKey = store.getKey(alias, password != null ? password.toCharArray() : null);
                    Key actualKey = keyManager.getPrivateKey(alias);
                    Assert.assertEquals(expectedKey, actualKey);
                }
            }
        }
    }

    @Test
    public void testTLS() {
        AtomicBoolean isServerStarted = new AtomicBoolean(false);
        ServerThread serverThread = new ServerThread(isServerStarted);
        serverThread.start();
        while (!isServerStarted.get()) {
            try {
                Thread.sleep(10L);
            } catch (InterruptedException e) {
                System.err.println(e.getMessage());
            }
        }
        startClient(serverThread.getServerPort());
    }

    private class ServerThread extends Thread {
        private int serverPort;

        private AtomicBoolean isServerStarted;

        ServerThread(AtomicBoolean isServerStarted) {
            this.isServerStarted = isServerStarted;
        }

        public void setServerPort(int serverPort) {
            this.serverPort = serverPort;
        }

        public int getServerPort() {
            return serverPort;
        }

        @Override
        public void run() {
            startServer(0, isServerStarted);
        }
        private void startServer(int serverPort, AtomicBoolean isServerStarted) {
            String[] expectedPaths = getPaths(new String[]{
                    "server-rsa.keystore",
                    "server-ec.keystore",
                    "server-sm2-sig.keystore",
                    "server-sm2-enc.keystore"
            });
            ServerSocket serverSocket = null;
            try {
                System.setProperty("javax.net.ssl.keyStore", arrayToString(expectedPaths));
                System.setProperty("javax.net.ssl.keyStoreType", PKCS12);
                System.setProperty("javax.net.ssl.keyStorePassword", PASSWD);
                SSLContext sslContext = SSLContext.getInstance("TLS", BGMJSSEPROVIDER);
                KeyManager[] keyManagers = getKeyManagers();
                sslContext.init(keyManagers, null, null);
                SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
                serverSocket = ssf.createServerSocket(serverPort);
                isServerStarted.set(true);
                setServerPort(serverSocket.getLocalPort());
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                String message = inputStream.readUTF();
                System.out.println("server receive : " + message);
            } catch (Exception e) {
                isServerStarted.set(true);
                throw new RuntimeException(e);
            } finally {
                System.getProperties().remove("javax.net.ssl.keyStore");
                System.getProperties().remove("javax.net.ssl.keyStoreType");
                System.getProperties().remove("javax.net.ssl.keyStorePassword");
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



    private void startClient(int serverPort) {
        Socket socket = null;
        try {
            SSLContext sslContext = SSLContext.getInstance("GMTLS");
            KeyStore ks = loadKeyStore(getPath("server.keystore"),
                    PKCS12, PASSWD);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            sslContext.init(null, tmf.getTrustManagers(), null);
            SSLSocketFactory sf = sslContext.getSocketFactory();
            socket = sf.createSocket("localhost", serverPort);
            DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
            String message = "Hello Server";
            System.out.println("Client send : " + message);
            outputStream.writeUTF(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println(e.getMessage());
                }
            }
        }
    }

    private static KeyManager[] getKeyManagers() throws Exception {
        Class<?> clazz = Class.forName(BGM_DEFAULTMANAGERSHOLDER_CLASS_NAME);
        Method method = clazz.getDeclaredMethod("getKeyManagers");
        method.setAccessible(true);
        return (KeyManager[]) method.invoke(null);
    }
}
