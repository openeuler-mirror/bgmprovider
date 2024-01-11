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

class BGMJSSEConfig {
    private static boolean enableKeyManagerFactory = true;
    private static boolean enableTrustManagerFactory = true;
    private static boolean enableKeyGenerator = true;
    private static boolean enableSSLContext = true;
    private static boolean enableKeyStore = true;

    static {
        initConfig();
    }

    private static void initConfig() {
        enableKeyManagerFactory = Config.enable("jsse.keyManagerFactory");
        enableTrustManagerFactory = Config.enable("jsse.trustManagerFactory");
        enableKeyGenerator = Config.enable("jsse.keyGenerator");
        enableSSLContext = Config.enable("jsse.sslContext");
        enableKeyStore = Config.enable("jsse.keystore");
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
}
