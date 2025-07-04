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

package org.openeuler.sdf.commons.constant;

import org.openeuler.sdf.commons.util.SDFTestUtil;

import java.io.File;

public interface SDFTestConstant {
    String JAVA_PATH =
            System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
    String CLASSPATH = System.getProperty("java.class.path");

    String SERVER_CLASS = "org.openeuler.sdf.jsse.gmtls.SDFGMTLSServer";
    String CLIENT_CLASS = "org.openeuler.sdf.jsse.gmtls.SDFGMTLSClient";

    String PATH_ROOT = SDFTestUtil.getResource("gmtls");

    String ENC_SERVER_KEYSTORE_PATH = PATH_ROOT + File.separator + "server.keystore";
    String ENC_SERVER_TRUSTSTORE_PATH = PATH_ROOT + File.separator + "server.truststore";
    String ENC_CLIENT_KEYSTORE_PATH = PATH_ROOT + File.separator + "client.keystore";
    String ENC_CLIENT_TRUSTSTORE_PATH = PATH_ROOT + File.separator + "client.truststore";

    String PLAIN_SERVER_KEYSTORE_PATH = PATH_ROOT + File.separator + "plain-server.keystore";
    String PLAIN_SERVER_TRUSTSTORE_PATH = PATH_ROOT + File.separator + "plain-server.truststore";
    String PLAIN_CLIENT_KEYSTORE_PATH = PATH_ROOT + File.separator + "plain-client.keystore";
    String PLAIN_CLIENT_TRUSTSTORE_PATH = PATH_ROOT + File.separator + "plain-client.truststore";

    String STORE_TYPE = "PKCS12";
    String STORE_PASSWORD = "12345678";
}
