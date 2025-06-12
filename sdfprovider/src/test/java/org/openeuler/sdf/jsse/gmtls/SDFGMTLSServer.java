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

package org.openeuler.sdf.jsse.gmtls;

import org.openeuler.BGMJCEProvider;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.Provider;
import java.security.Security;

public class SDFGMTLSServer {
    static {
        System.setProperty("sdf.sdkConfig", SDFTestUtil.getSdkConfig());
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("args len should not less than 2");
        }

        int idx = 0;
        boolean useEncMode = Boolean.parseBoolean(args[idx++]);
        int serverPort = Integer.parseInt(args[idx]);

        start(useEncMode, serverPort);
    }

    static int start(boolean useEncMode) throws Exception {
        return start(useEncMode, 0);
    }

    private static int start(boolean useEncMode,int serverPort) throws Exception {
        Provider jceProvider = useEncMode ? new SDFProvider() : new BGMJCEProvider();
        Security.insertProviderAt(jceProvider, 1);
        Security.insertProviderAt(new BGMJSSEProvider(), 2);

        SSLContext sslContext = SSLContext.getDefault();
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
        ServerSocket serverSocket = serverSocketFactory.createServerSocket(serverPort);
        Thread thread = new Thread(()->{
            try {
                handle(serverSocket);
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
        });
        thread.setName("Server");
        thread.start();
        serverPort = serverSocket.getLocalPort();
        System.err.println("serverPort=" + serverPort);
        return serverPort;
    }

    private static void handle(ServerSocket serverSocket) throws IOException {
        SSLSocket socket = null;
        try {
            socket = (SSLSocket) serverSocket.accept();
            DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream inputStream = new DataInputStream(socket.getInputStream());
            for (int i = 0; i < 2 ; i++) {
                handleMessage(outputStream, inputStream);
            }
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println(e.getMessage());
                }
            }
            try {
                serverSocket.close();
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
        }
    }

    private static void handleMessage(DataOutputStream dataOutputStream, DataInputStream dataInputStream)
            throws IOException {
        String readMessage = dataInputStream.readUTF();
        System.out.println("server receive : " + readMessage);
        String sendMessage = "Hello Client";
        dataOutputStream.writeUTF(sendMessage);
        System.out.println("server send : " + sendMessage);
        dataOutputStream.flush();
    }
}
