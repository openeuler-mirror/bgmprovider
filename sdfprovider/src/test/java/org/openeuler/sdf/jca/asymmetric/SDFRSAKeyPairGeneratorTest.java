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

package org.openeuler.sdf.jca.asymmetric;

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.Provider;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class SDFRSAKeyPairGeneratorTest {

    private static final Provider provider = new SDFProvider();

    // 1024,2048,3072,4096
    private static final int[] VALID_KEY_SIZES = {1024, 2048, 3072, 4096};

    private static final int[] INVALID_KEY_SIZES = {1023, 2043, 3071, 4097};

    @Test
    public void testValidKeySize() throws Exception {
        if (!SDFTestUtil.isEnableNonSM()) {
            System.out.println("skip test case testValidKeySize");
            return;
        }
        for (int keySize : VALID_KEY_SIZES) {
            System.out.println("test keySize :" + keySize);
            testValidKeySize(keySize);
        }
    }

    @Test
    public void testInValidKey() {
        if (!SDFTestUtil.isEnableNonSM()) {
            System.out.println("skip test case testInValidKey");
            return;
        }
        for (int keySize : INVALID_KEY_SIZES) {
            System.out.println("test keySize :" + keySize);
            testInvalidKeySize(keySize);
        }
    }

    private static void testValidKeySize(int keySize) throws Exception {
        KeyPair keyPair = SDFRSATestUtil.generateKeyPair(keySize, provider);
        Assert.assertTrue(keyPair.getPrivate() instanceof RSAPrivateCrtKey);
        Assert.assertTrue(keyPair.getPublic() instanceof RSAPublicKey);

        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        Assert.assertEquals("Moduli do not match",
                privateKey.getModulus(), publicKey.getModulus());
        Assert.assertEquals("Exponents do not match",
                publicKey.getPublicExponent(), privateKey.getPublicExponent());
        int keyLen = publicKey.getModulus().bitLength();
        if ((keyLen > keySize) || (keyLen < keySize - 1)) {
            throw new Exception("Incorrect key length: " + keyLen);
        }

        BigInteger n = privateKey.getModulus();
        BigInteger e = privateKey.getPublicExponent();
        BigInteger d = privateKey.getPrivateExponent();
        BigInteger p = privateKey.getPrimeP();
        BigInteger q = privateKey.getPrimeQ();
        BigInteger pe = privateKey.getPrimeExponentP();
        BigInteger qe = privateKey.getPrimeExponentQ();
        BigInteger coeff = privateKey.getCrtCoefficient();

        Assert.assertEquals("n != p * q ", n, p.multiply(q));
        Assert.assertEquals("pe != d mod (p -1)", pe, d.mod(p.subtract(BigInteger.ONE)));
        Assert.assertEquals("qe != d mod (q -1)", qe, d.mod(q.subtract(BigInteger.ONE)));
        Assert.assertEquals("coeff !=q.modInverse(p)", coeff, q.modInverse(p));
        Assert.assertEquals("((p - 1) *(q - 1)) % (ed -1) != 0",
                BigInteger.ZERO, pe.multiply(qe).divide(e.multiply(d).multiply(BigInteger.ONE)));
    }

    private static void testInvalidKeySize(int keySize) {
        boolean hasException = false;
        try {
            SDFRSATestUtil.generateKeyPair(keySize, provider);
        } catch (Exception e) {
            hasException = true;
            Assert.assertTrue(e instanceof InvalidParameterException);
        }
        if (!hasException) {
            throw new RuntimeException("test failed");
        }
    }
}
