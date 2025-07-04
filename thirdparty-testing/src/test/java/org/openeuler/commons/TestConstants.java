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

package org.openeuler.commons;

public class TestConstants {
    public static final String TLS13_PROTOCOL = "TLSv1.3";
    public static final String TLS_AES_128_GCM_SHA256 = "TLS_AES_128_GCM_SHA256";
    public static final String GMTLS_PROTOCOL = "GMTLS";
    public static final String ECC_SM4_CBC_SM3= "ECC_SM4_CBC_SM3";
    public static final String ECC_SM4_GCM_SM3 = "ECC_SM4_GCM_SM3";
    public static final String ECDHE_SM4_CBC_SM3 = "ECDHE_SM4_CBC_SM3";
    public static final String ECDHE_SM4_GCM_SM3 = "ECDHE_SM4_GCM_SM3";

    public static final String SERVER_KEYSTORE_PATH = TestUtils.getPath("server.keystore");
    public static final String SERVER_KEYSTORE_PASSWORD = "12345678";
    public static final String SERVER_TRUSTSTORE_PATH = TestUtils.getPath("server.truststore");
    public static final String SERVER_TRUSTSTORE_PASSWORD = "12345678";

    public static final String CLIENT_KEYSTORE_PATH = TestUtils.getPath("client.keystore");
    public static final String CLIENT_KEYSTORE_PASSWORD = "12345678";
    public static final String CLIENT_TRUSTSTORE_PATH = TestUtils.getPath("client.truststore");
    public static final String CLIENT_TRUSTSTORE_PASSWORD = "12345678";

    public static final String SDK_CONFIG_PATH = TestUtils.getPath("sdf/sdk.config");
    public static final String ENC_SERVER_KEYSTORE_PATH = TestUtils.getPath("sdf/server.keystore");
    public static final String ENC_SERVER_KEYSTORE_PASSWORD = "12345678";
    public static final String ENC_SERVER_TRUSTSTORE_PATH = TestUtils.getPath("sdf/server.truststore");
    public static final String ENC_SERVER_TRUSTSTORE_PASSWORD = "12345678";

    public static final String ENC_CLIENT_KEYSTORE_PATH = TestUtils.getPath("sdf/client.keystore");
    public static final String ENC_CLIENT_KEYSTORE_PASSWORD = "12345678";
    public static final String ENC_CLIENT_TRUSTSTORE_PATH = TestUtils.getPath("sdf/client.truststore");
    public static final String ENC_CLIENT_TRUSTSTORE_PASSWORD = "12345678";
}
