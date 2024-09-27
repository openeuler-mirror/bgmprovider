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

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * SSLSocket Test
 */
public class SDFSSLSocketTest extends SDFSSLSocketTestBase {

    @BeforeClass
    public static void beforeClass() {
//        System.setProperty("javax.net.debug", "all");
        System.setProperty("jdk.tls.client.protocols", "TLSv1.3,TLSv1.2,GMTLS");
        init();
    }

    @Test
    public void testGMTLSContextECDHE() {
        test("GMTLS", null, null,
                "GMTLS", new String[]{"GMTLS"}, new String[]{"ECDHE_SM4_CBC_SM3"}, true);
    }

    @Test
    public void testGMTLSContextECC() {
        test("GMTLS", null, null,
                "GMTLS", new String[]{"GMTLS"}, new String[]{"ECC_SM4_CBC_SM3"});
    }
}
