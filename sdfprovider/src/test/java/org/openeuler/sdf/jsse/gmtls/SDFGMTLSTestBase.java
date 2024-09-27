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

import org.junit.Assert;
import org.openeuler.sdf.jsse.util.SDFGMTLTestUtil;

import static org.openeuler.sdf.jsse.util.SDFGMTLTestUtil.SERVER_PORT;
import static org.openeuler.sdf.jsse.util.SDFGMTLTestUtil.getClientCommand;
import static org.openeuler.sdf.jsse.util.SDFGMTLTestUtil.getServerCommand;

public class SDFGMTLSTestBase {

    public static void test(boolean serverUseEnc, boolean clientUseEnc, String protocol, String cipherSuite)
            throws Exception {
        SDFGMTLTestUtil.setServerSysProps(serverUseEnc, clientUseEnc);
        int serverPort = SDFGMTLSServer.start(serverUseEnc);
        String clientCommand = SDFGMTLTestUtil.getClientCommand(
                serverUseEnc, clientUseEnc, serverPort, protocol, cipherSuite);
        System.out.println("clientCommand=" + clientCommand);
        Process clientProcess = Runtime.getRuntime().exec(clientCommand);
        clientProcess.waitFor();
        String errorMessage = SDFGMTLTestUtil.getErrorMessage(clientProcess);

        System.out.println("errorMessage :");
        System.out.println(errorMessage);
        String logMessage = SDFGMTLTestUtil.getLogMessage(clientProcess);
        System.out.println("logMessage :");
        System.out.println(logMessage);

        Assert.assertNull(errorMessage);
    }

    private static void testEncServerAndEncClient() throws Exception {

        String serverCommand = getServerCommand(true, true,SERVER_PORT);
        System.out.println("serverCommand=" + serverCommand);
        String clientCommand = getClientCommand(true, true, SERVER_PORT, "GMTLS", "ECC_SM4_CBC_SM3");
        System.out.println("clientCommand=" + clientCommand);
    }

    private void testEncServerAndPlainClient() throws Exception {
        String serverCommand = getServerCommand(true, false, SERVER_PORT);
        System.out.println("serverCommand=" + serverCommand);
        String clientCommand = getClientCommand(true, false, SERVER_PORT, "GMTLS", "ECC_SM4_CBC_SM3");
        System.out.println("clientCommand=" + clientCommand);
    }

    private void testPlainServerAndEncClient() throws Exception {
        String serverCommand = getServerCommand(false, true, SERVER_PORT);
        System.out.println("serverCommand=" + serverCommand);
        String clientCommand = getClientCommand(false, true, SERVER_PORT, "GMTLS", "ECC_SM4_CBC_SM3");
        System.out.println("clientCommand=" + clientCommand);
    }

    private void testPlainServerAndPlainClient() throws Exception {
        String serverCommand = getServerCommand(false, false, SERVER_PORT);
        System.out.println("serverCommand=" + serverCommand);
        String clientCommand = getClientCommand(false, false, SERVER_PORT, "GMTLS", "ECC_SM4_CBC_SM3");
        System.out.println("clientCommand=" + clientCommand);
    }

    /*public static void main(String[] args) throws Exception {
        testEncServerAndEncClient();
    }*/

}
