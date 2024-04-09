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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.org.bouncycastle.SM2ParameterSpec;
import sun.security.x509.AlgorithmId;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertTrue;

/**
 * SM3withSM2 signature test
 */
public class SM3withSM2Test {
    private static final byte[] INFO = "SM3withSM2 test".getBytes();

    private static final byte[] PUBLIC_KEY_BYTES = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42,
            -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, 10, -36, -22, -20, 17,
            26, 86, -114, -52, -78, 79, -22, 116, -47, -70, -33, 112, 32, -18, 92, -45,
            -58, 20, 36, -5, 55, 68, -95, -57, -121, 10, 33, -76, 54, 24, -119, -104,
            61, -24, -113, 46, -57, 36, -78, -37, -95, -113, -52, -88, -5, 22, -67, 101,
            94, 37, 2, -58, 55, -35, 15, -21, 31, -49, -80
    };
    private static final byte[] PRIVATE_KEY_BYTES = new byte[]{
            48, -127, -109, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2,
            1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 121, 48, 119, 2,
            1, 1, 4, 32, -104, 71, 54, -41, 24, 66, 82, -45, 114, -113, -121, -105,
            -35, 35, 9, 49, -8, 119, 44, 118, 80, -20, 47, -38, -69, -47, 121, -8,
            -73, -33, 4, 54, -96, 10, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45,
            -95, 68, 3, 66, 0, 4, 10, -36, -22, -20, 17, 26, 86, -114, -52, -78,
            79, -22, 116, -47, -70, -33, 112, 32, -18, 92, -45, -58, 20, 36, -5, 55,
            68, -95, -57, -121, 10, 33, -76, 54, 24, -119, -104, 61, -24, -113, 46, -57,
            36, -78, -37, -95, -113, -52, -88, -5, 22, -67, 101, 94, 37, 2, -58, 55,
            -35, 15, -21, 31, -49, -80
    };

    private static final byte[] SIGN_BYTES = new byte[]{
            48, 69, 2, 33, 0, -31, -74, -78, -97, 64, -7, 85, -95, 100, 88, -83,
            10, -121, -122, 22, -61, 7, 127, -52, -35, -86, -109, -46, -112, 63, 75, -16,
            34, -30, -85, 71, -60, 2, 32, 36, -103, -2, -56, 117, 110, -79, 5, 73,
            -116, -19, -60, -112, 64, -122, -20, -37, 44, -38, 104, 60, 76, 41, -48, -40,
            25, -59, 38, -44, 27, -64, -60
    };

    private static PrivateKey privateKey;

    private static PublicKey publicKey;

    /**
     * Init private key and public key
     */
    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(PUBLIC_KEY_BYTES));
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES));
    }

    /**
     * Test sign and verify
     */
    @Test
    public void testVerify() throws Exception {
        boolean verify = verify(SIGN_BYTES);
        assertTrue(verify);
    }

    @Test
    public void testSignAndVerify() throws Exception {
        byte[] signBytes = sign();
        boolean verify = verify(signBytes);
        assertTrue(verify);
    }

    private byte[] sign() throws Exception {
        Signature signature = Signature.getInstance("SM3withSM2");
        signature.initSign(privateKey);
        signature.update(INFO);
        return signature.sign();
    }

    private boolean verify(byte[] signBytes) throws Exception {
        Signature signature = Signature.getInstance("SM3withSM2");
        signature.initVerify(publicKey);
        signature.update(INFO);
        return signature.verify(signBytes);
    }

    @Test
    public void getParameters() throws Exception{
        if (BGMJCEConfig.useLegacy()) {
            return;
        }
        Signature signature = Signature.getInstance("SM3withSM2");
        signature.initSign(privateKey);
        Assert.assertNull(signature.getParameters());

        signature.setParameter(new SM2ParameterSpec("1234567812345678".getBytes()));
        Assert.assertNull(signature.getParameters());

        ECParameterSpec parameterSpec = ((ECPrivateKey) privateKey).getParams();
        signature.setParameter(new SM2ParameterSpec("1234567812345678".getBytes(), parameterSpec));
        Assert.assertNotNull(signature.getParameters());
    }
}
