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

package org.openeuler;

import org.openeuler.util.ConfigUtil;

public class BGMJSSEConfig {
    private static boolean enableKeyManagerFactory = true;
    private static boolean enableTrustManagerFactory = true;
    private static boolean enableKeyGenerator = true;
    private static boolean enableSSLContext = true;
    private static boolean enableKeyStore = true;

    // Support RFC 8998 : ShangMi (SM) Cipher Suites for TLS 1.3
    private static boolean enableRFC8998 = false;

    static {
        initConfig();
    }

    private static void initConfig() {
        enableKeyManagerFactory = ConfigUtil.enable("jsse.keyManagerFactory");
        enableTrustManagerFactory = ConfigUtil.enable("jsse.trustManagerFactory");
        enableKeyGenerator = ConfigUtil.enable("jsse.keyGenerator");
        enableSSLContext = ConfigUtil.enable("jsse.sslContext");
        enableKeyStore = ConfigUtil.enable("jsse.keystore");
        enableRFC8998 = ConfigUtil.enable("bgmprovider.tls.enableRFC8998", "false");
    }

    private BGMJSSEConfig() {

    }

    static boolean enableKeyManagerFactory() {
        return enableKeyManagerFactory;
    }

    static boolean enableTrustManagerFactory() {
        return enableTrustManagerFactory;
    }

    static boolean enableKeyGenerator() {
        return enableKeyGenerator;
    }

    static boolean enableSSLContext() {
        return enableSSLContext;
    }

    static boolean enableKeyStore() {
        return enableKeyStore;
    }

    public static boolean enableRFC8998() {
        return enableRFC8998;
    }
}
