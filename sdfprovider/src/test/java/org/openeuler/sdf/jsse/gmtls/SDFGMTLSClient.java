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
import org.openeuler.sdf.provider.SDFProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

public class SDFGMTLSClient {
    /**
     * @param args  serverPort useEncMode
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("args len should not less than 2");
        }

        int idx = 0;
        boolean useEncMode = Boolean.parseBoolean(args[idx++]);
        int serverPort = Integer.parseInt(args[idx++]);

        Provider jceProvider = useEncMode ? new SDFProvider() : new BGMJCEProvider();
        Security.insertProviderAt(jceProvider, 1);
        Security.insertProviderAt(new BGMJSSEProvider(), 2);

        SSLContext sslContext = SSLContext.getDefault();
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", serverPort);

        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
        DataInputStream inputStream = new DataInputStream(socket.getInputStream());
        for (int i = 0; i < 2; i++) {
            handleMessage(outputStream, inputStream);
        }
    }

    public static void handleMessage(DataOutputStream outputStream, DataInputStream inputStream)
            throws IOException {
        String sendMessage = "Hello Server";
        outputStream.writeUTF(sendMessage);
        System.out.println("client send : " + sendMessage);
        outputStream.flush();

        String readMessage = inputStream.readUTF();
        System.out.println("client receive : " + readMessage);
    }
}
