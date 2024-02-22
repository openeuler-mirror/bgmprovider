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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

public class AlpnExtensionSSLEngineTest extends BaseTest {
    private static final byte[] MESSAGE = "hello world".getBytes();
    private static final String HOST = "localhost";
    private static volatile int PORT = 0;
    private static final String STORE_TYPE = "PKCS12";
    private static final String PASSWORD = "12345678";
    private static final String APPLICATION_PROTOCOL = "h2";

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("javax.net.debug", "all");
        System.setProperty("javax.net.ssl.keyStore", TestUtils.getPath("server.keystore"));
        System.setProperty("javax.net.ssl.keyStoreType", STORE_TYPE);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWORD);

        System.setProperty("javax.net.ssl.trustStore", TestUtils.getPath("server.truststore"));
        System.setProperty("javax.net.ssl.trustStoreType", STORE_TYPE);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
    }

    @Test
    public void test() throws Exception {
        SSLContext sslContext = SSLContext.getDefault();

        // client engine
        SSLEngine clientEngine = sslContext.createSSLEngine(HOST, PORT);
        clientEngine.setUseClientMode(true);
        SSLParameters sslParameters = clientEngine.getSSLParameters();
        sslParameters.setProtocols(new String[]{"GMTLS"});
        sslParameters.setApplicationProtocols(new String[]{"h2"});
        clientEngine.setSSLParameters(sslParameters);

        // server engine
        SSLEngine serverEngine = sslContext.createSSLEngine();
        serverEngine.setUseClientMode(false);
        sslParameters = serverEngine.getSSLParameters();
        sslParameters.setProtocols(new String[]{"GMTLS"});
        sslParameters.setApplicationProtocols(new String[]{"h2"});
        serverEngine.setSSLParameters(sslParameters);

        // create buffer
        ByteBuffer clientOut = ByteBuffer.wrap(MESSAGE);
        ByteBuffer serverOut = ByteBuffer.wrap(MESSAGE);
        SSLSession session = clientEngine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();
        ByteBuffer clientIn = ByteBuffer.allocate(appBufferMax + 50);
        ByteBuffer serverIn = ByteBuffer.allocate(appBufferMax + 50);
        ByteBuffer cTOs = ByteBuffer.allocate(netBufferMax);
        ByteBuffer sTOc = ByteBuffer.allocate(netBufferMax);

        clientEngine.wrap(clientOut, cTOs);
        runDelegatedTasks(clientEngine);
        cTOs.flip();
        serverEngine.unwrap(cTOs, serverIn);
        runDelegatedTasks(serverEngine);

        serverEngine.wrap(serverOut, sTOc);
        runDelegatedTasks(clientEngine);
        sTOc.flip();
        clientEngine.unwrap(sTOc, clientIn);
        runDelegatedTasks(clientEngine);

        Assert.assertEquals(APPLICATION_PROTOCOL, clientEngine.getApplicationProtocol());
        Assert.assertEquals(APPLICATION_PROTOCOL, serverEngine.getApplicationProtocol());
    }

    private static void runDelegatedTasks(SSLEngine engine) throws Exception {
        if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
        }
    }
}
