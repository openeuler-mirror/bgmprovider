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
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.constant.SDFConstant;
import org.openeuler.sdf.commons.util.SDFKeyTestDB;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.provider.SDFProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class SDFSM2KeyPairGeneratorTest extends SDFTestCase {

    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testGenerateEncKeyPair() throws Exception {
        testEncKey();
    }

    @Test
    public void test() throws Exception {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(false);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) encKeyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) encKeyPair.getPublic();
        System.out.println(Arrays.toString(ecPrivateKey.getS().toByteArray()));
        System.out.println(Arrays.toString(ecPublicKey.getEncoded()));
    }
    @Test
    public void testGenerateKeyPair() throws Exception {

        byte[] pubKeyBytes = SDFKeyTestDB.SM2_KEY_PAIR.getPubKey();
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        byte[] privateKeyBytes = SDFKeyTestDB.SM2_KEY_PAIR.getEncKey();
        SDFECPrivateKeyImpl privateKey = new SDFECPrivateKeyImpl(
                new BigInteger(1, privateKeyBytes),
                publicKey.getParams());
        System.out.println(privateKey);
    }

    public static void testEncKey() throws Exception {
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(true);

        // check private key
        Assert.assertTrue(encKeyPair.getPrivate() instanceof ECPrivateKey);
        ECPrivateKey privateKey = (ECPrivateKey) encKeyPair.getPrivate();
        byte[] sBytes = privateKey.getS().toByteArray();
        Assert.assertEquals(SDFConstant.ENC_SM2_PRIVATE_KEY_SIZE, sBytes.length);

        // check public key
        Assert.assertTrue(encKeyPair.getPublic() instanceof ECPublicKey);
        ECPublicKey publicKey = (ECPublicKey) encKeyPair.getPublic();
        byte[] xBytes = publicKey.getW().getAffineX().toByteArray();
        byte[] yBytes = publicKey.getW().getAffineY().toByteArray();
        Assert.assertTrue(SDFConstant.SM2_PUBLIC_KEY_X_LEN <= xBytes.length
                && xBytes.length <= SDFConstant.SM2_PUBLIC_KEY_X_LEN + 1);
        Assert.assertTrue(SDFConstant.SM2_PUBLIC_KEY_Y_LEN <= yBytes.length
                && yBytes.length <= SDFConstant.SM2_PUBLIC_KEY_Y_LEN + 1);
    }
}
