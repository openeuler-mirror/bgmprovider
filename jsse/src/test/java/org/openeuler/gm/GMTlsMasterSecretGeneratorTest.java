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
import org.openeuler.sun.security.internal.spec.TlsMasterSecretParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * GMTlsMasterSecretGenerator test
 */
@SuppressWarnings("deprecation")
public class GMTlsMasterSecretGeneratorTest extends BaseTest {

    // client random bytes
    private static final byte[] CLIENT_RANDOM_BYTES = new byte[]{
            34, -13, -128, 41, -88, 102, -99, 94, -97, 8, -7, 14, 48, -88, 14, 36,
            -81, 109, 124, 76, -43, -11, 114, 61, -100, 96, -74, 74, -13, -51, 39, 49
    };

    // server random bytes
    private static final byte[] SERVER_RANDOM_BYTES = new byte[]{
            8, -90, -57, -28, -109, 23, 75, -64, -29, -44, -99, -118, -69, -64, -28, 53,
            -83, -111, -9, -104, 69, -90, -4, -23, 61, 22, -96, 70, 113, 94, -123, 24
    };

    // preMasterSecret
    private static SecretKey PRE_MASTER_SECRET = new SecretKeySpec(new byte[]{
            94, -65, -33, -21, 117, -104, -103, 68, 93, -118, -110, 79, 4, 89, -78, -100,
            95, -63, 13, 88, 94, 7, 31, 89, -27, 63, 15, 42, -66, 107, 45, -59,
            9, -37, 105, 73, 32, -104, 18, 28, 9, -15, 37, -22, 2, -126, -100, 91
    }, "TlsPremasterSecret");

    // expected master secret
    private static final byte[] EXPECTED_MASTER_SECRET = new byte[]{
            -64, 67, 17, 117, -76, 30, 3, -113, -113, 123, 12, -19, 12, 124, 86, -109,
            89, 0, -70, 99, -24, -86, 58, 6, -50, 6, -44, 55, 122, -100, 53, 20,
            50, 62, -45, -127, 107, -32, 17, -107, 101, -96, -73, -102, -92, -37, -51, 95
    };

    /**
     * Test generate master key
     */
    @Test
    public void testGenerateMasterKey()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        TlsMasterSecretParameterSpec parameterSpec = createParameterSpec(1, 1);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.init(parameterSpec);
        SecretKey masterSecret = keyGenerator.generateKey();
        Assert.assertArrayEquals(EXPECTED_MASTER_SECRET, masterSecret.getEncoded());
    }

    /**
     * Test not initialized before generating the key
     */
    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.generateKey();
    }


    /**
     * Test invalid AlgorithmParameterSpec
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testInvalidAlgorithmParameterSpec() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.init(new AlgorithmParameterSpec() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        });
    }

    /**
     * Test invalid GM TLS protocol version
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testInvalidGMTLSProtocolVersion()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        TlsMasterSecretParameterSpec parameterSpec = createParameterSpec(1, 0);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.init(parameterSpec);
    }

    private TlsMasterSecretParameterSpec createParameterSpec(int majorVersion, int minVersion) {
        return new TlsMasterSecretParameterSpec(
                PRE_MASTER_SECRET, majorVersion, minVersion, CLIENT_RANDOM_BYTES, SERVER_RANDOM_BYTES,
                "SM3", 32, 64);
    }
}
