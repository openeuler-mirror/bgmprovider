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

package org.openeuler.commons;

import org.openeuler.BGMJSSEProvider;
import org.openeuler.BGMProvider;
import org.openeuler.sdf.provider.SDFProvider;

import java.security.Security;

import static org.openeuler.commons.TestConstants.*;
import static org.openeuler.commons.TestConstants.ENC_CLIENT_KEYSTORE_PATH;

public class BaseTest {
    protected static String serverKeyStorePath;
    protected static String serverKeyStorePass;
    protected static String serverTrustStorePath;
    protected static String serverTrustStorePass;

    protected static String clientKeyStorePath;
    protected static String clientKeyStorePass;
    protected static String clientTrustStorePath;
    protected static String clientTrustStorePass;

    static {
        Security.insertProviderAt(new BGMProvider(), 1);
    }

    protected void initBGMProvider() {
        Security.removeProvider("SDFProvider");
        Security.removeProvider("BGMJSSEProvider");
        Security.insertProviderAt(new BGMProvider(), 1);

        serverKeyStorePath = SERVER_KEYSTORE_PATH;
        serverKeyStorePass = SERVER_KEYSTORE_PASSWORD;
        serverTrustStorePath = SERVER_TRUSTSTORE_PATH;
        serverTrustStorePass = SERVER_TRUSTSTORE_PASSWORD;

        clientKeyStorePath = CLIENT_KEYSTORE_PATH;
        clientKeyStorePass = CLIENT_KEYSTORE_PASSWORD;
        clientTrustStorePath = CLIENT_TRUSTSTORE_PATH;
        clientTrustStorePass = CLIENT_TRUSTSTORE_PASSWORD;
    }

    protected void initSDFProvider() {
        System.setProperty("sdf.sdkConfig", System.getProperty("sdf.sdkConfig", SDK_CONFIG_PATH));
        System.setProperty("sdf.defaultKEKId",
                System.getProperty("sdf.defaultKEKId", "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-a"));
        System.setProperty("sdf.defaultRegionId", System.getProperty("sdf.defaultRegionId", "RegionID1"));
        System.setProperty("sdf.defaultCdpId",
                System.getProperty("sdf.defaultCdpId", "cdp_id_length_need_32_0000000000"));

        Security.removeProvider("BGMProvider");
        Security.insertProviderAt(new BGMJSSEProvider(), 1);
        Security.insertProviderAt(new SDFProvider(), 1);

        serverKeyStorePath = ENC_SERVER_KEYSTORE_PATH;
        serverKeyStorePass = ENC_SERVER_KEYSTORE_PASSWORD;
        serverTrustStorePath = ENC_SERVER_TRUSTSTORE_PATH;
        serverTrustStorePass = ENC_SERVER_TRUSTSTORE_PASSWORD;

        clientKeyStorePath = ENC_CLIENT_KEYSTORE_PATH;
        clientKeyStorePass = ENC_CLIENT_KEYSTORE_PASSWORD;
        clientTrustStorePath = ENC_CLIENT_TRUSTSTORE_PATH;
        clientTrustStorePass = ENC_CLIENT_TRUSTSTORE_PASSWORD;
    }
}
