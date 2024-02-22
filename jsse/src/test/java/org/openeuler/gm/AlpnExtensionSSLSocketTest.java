/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

public class AlpnExtensionSSLSocketTest extends BaseTest {
    private static final byte[] MESSAGE = "hello world".getBytes();
    private static final String HOST = "localhost";
    private static volatile int PORT = 0;
    private static final String STORE_TYPE = "PKCS12";
    private static final String PASSWORD = "12345678";
    private static volatile boolean SERVER_STARTED;
    private static final String APPLICATION_PROTOCOL = "h2";

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("javax.net.ssl.keyStore", TestUtils.getPath("server.keystore"));
        System.setProperty("javax.net.ssl.keyStoreType", STORE_TYPE);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWORD);

        System.setProperty("javax.net.ssl.trustStore", TestUtils.getPath("server.truststore"));
        System.setProperty("javax.net.ssl.trustStoreType", STORE_TYPE);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
    }

    @Test
    public void test() throws IOException, InterruptedException {
        new Thread(() -> {
            try {
                startServer();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).start();

        startClient();
    }

    private static void startServer() throws IOException {
        ServerSocketFactory serverSocketFactory = SSLServerSocketFactory.getDefault();
        try (SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT)) {
            PORT = serverSocket.getLocalPort();
            SERVER_STARTED = true;
            SSLSocket socket = (SSLSocket) serverSocket.accept();
            SSLParameters sslParameters = socket.getSSLParameters();
            sslParameters.setProtocols(new String[]{"GMTLS"});
            sslParameters.setApplicationProtocols(new String[]{APPLICATION_PROTOCOL});
            socket.setSSLParameters(sslParameters);
            byte[] bytes = new byte[MESSAGE.length];
            socket.getInputStream().read(bytes);
            Assert.assertArrayEquals(MESSAGE, bytes);
            Assert.assertEquals(APPLICATION_PROTOCOL, socket.getApplicationProtocol());
        }
    }

    private static void startClient() throws IOException, InterruptedException {
        SocketFactory socketFactory = SSLSocketFactory.getDefault();
        while (!SERVER_STARTED) {
            Thread.sleep(100);
        }
        try (SSLSocket socket = (SSLSocket) socketFactory.createSocket(HOST, PORT)) {
            SSLParameters sslParameters = socket.getSSLParameters();
            sslParameters.setApplicationProtocols(new String[]{APPLICATION_PROTOCOL});
            sslParameters.setProtocols(new String[]{"GMTLS"});
            socket.setSSLParameters(sslParameters);
            socket.getOutputStream().write(MESSAGE);
            Assert.assertEquals(APPLICATION_PROTOCOL, socket.getApplicationProtocol());
        }
    }
}
