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

package org.openeuler.sdf.jca.symmetric;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sdf.provider.SDFProvider;

import java.security.Security;

public class SDFSM1Test extends SDFSymmetricTest {
    private static final int BLOCK_SIZE = 16;
    private static final int KEY_SIZE = 128;
    private static final int IV_LEN = 16;
    private static final String ALGO = "SM1";

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testECB() throws Exception {
        testECB(ALGO, BLOCK_SIZE, KEY_SIZE);
    }

    @Test
    public void testCBC() throws Exception {
        testCBC(ALGO, BLOCK_SIZE, KEY_SIZE, IV_LEN);
    }

    @Test
    public void testCTR() throws Exception {
        testCTR(ALGO, BLOCK_SIZE, KEY_SIZE, IV_LEN);
    }
}
