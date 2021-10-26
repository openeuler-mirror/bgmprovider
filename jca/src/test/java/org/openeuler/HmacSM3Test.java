/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * HmacSM3 test
 */
public class HmacSM3Test {
    private static final byte[] INFO = "HmacSM3 test".getBytes();

    private static final byte[] EXPECTED_MAC = new byte[]{
            102, -114, 51, 6, -78, -7, 92, 95, -90, -110, -49, 48, -42, -122, -109, 56, 18, -93, 28, 120, 34, -46, -116, -98, 53, 68, 8, -116, 30, -72, 68, 105
    };

    private static final SecretKey secretKey = generateKey();

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void testMac() throws Exception {
        byte[] macBytes = mac(secretKey);
        assertArrayEquals(EXPECTED_MAC, macBytes);
        byte[] macAgainBytes = mac(secretKey);
        assertArrayEquals(macBytes, macAgainBytes);
    }

    @Test
    public void testKeyGenerateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSM3");
        SecretKey secretKey = keyGenerator.generateKey();
        assertEquals(secretKey.getEncoded().length, 32);
    }

    private byte[] mac(SecretKey secretKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSM3");
        mac.init(secretKey);
        mac.update(INFO);
        return mac.doFinal();
    }

    private static SecretKey generateKey() {
        return new SecretKeySpec("123456".getBytes(), "HmacSM3");
    }
}
