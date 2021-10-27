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

package org.openeuler.gm;

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.sun.security.internal.spec.TlsPrfParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * GMTlsPrfGenerator test
 */
@SuppressWarnings("deprecation")
public class GMTlsPrfGeneratorTest extends BaseTest {

    // tls label
    private static final String TLS_LABEL = "client finished";

    // master secret key
    private static final SecretKey MASTER_SECRET_KEY = new SecretKeySpec(new byte[]{
            -64, 67, 17, 117, -76, 30, 3, -113, -113, 123, 12, -19, 12, 124, 86, -109,
            89, 0, -70, 99, -24, -86, 58, 6, -50, 6, -44, 55, 122, -100, 53, 20,
            50, 62, -45, -127, 107, -32, 17, -107, 101, -96, -73, -102, -92, -37, -51, 95
    }, "TlsMasterSecret");

    // seed
    private static final byte[] SEED = new byte[]{
            -94, 72, 103, 112, 86, -94, 88, -2, 32, -70, 109, -39, -106, 101, 110, 66,
            2, -89, -115, -19, -117, 95, 21, 68, 31, -101, 88, 115, -36, -26, -67, -56
    };

    // expected prf secret key
    private static final byte[] EXPECTED_PRF_SECRET_KEY = new byte[]{
            -29, 51, 46, 8, 93, -112, 121, -113, -40, -60, -107, -7
    };

    /**
     * Test generate Key
     */
    @Test
    public void testGenerateKey() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        TlsPrfParameterSpec tlsPrfParameterSpec = new TlsPrfParameterSpec(
                MASTER_SECRET_KEY, TLS_LABEL, SEED, 12,
                "SM3", 32, 64);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        keyGenerator.init(tlsPrfParameterSpec);
        SecretKey prfSecretKey = keyGenerator.generateKey();
        Assert.assertArrayEquals(EXPECTED_PRF_SECRET_KEY, prfSecretKey.getEncoded());
    }

    /**
     * Test not initialized before generating the key
     */
    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        keyGenerator.generateKey();
    }

    /**
     * Test invalid AlgorithmParameterSpec
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testInvalidAlgorithmParameterSpec() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        keyGenerator.init(new AlgorithmParameterSpec() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        });
    }
}
