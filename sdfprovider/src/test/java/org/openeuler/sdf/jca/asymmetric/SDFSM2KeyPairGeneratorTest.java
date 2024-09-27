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
import org.junit.Ignore;
import org.junit.Test;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.Cipher;
import java.security.*;

import static org.junit.Assert.assertArrayEquals;

public class SDFSM2KeyPairGeneratorTest {
    private static final byte[] INFO = "SM2 test".getBytes();

    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testGenerateEncKeyPair() throws Exception {
        testEncKey(INFO);
    }

    @Test
    public void testGenerateEncKeyPairRandomly() throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        testEncKey(randomBytes);
    }

    @Test
    @Ignore
    public void testGeneratePlainKeyPair() throws Exception {
         testNormalKey(INFO);
    }

    @Test
    @Ignore
    public void testGeneratePlainKeyPairRandomly() throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        testNormalKey(randomBytes);
    }

    public static void testNormalKey(byte[] plainTextBytes) throws Exception {
        KeyPair normalKeyPair = SDFSM2TestUtil.generateKeyPair(false);
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.ENCRYPT_MODE, normalKeyPair.getPublic());
        byte[] encRes = cipher.doFinal(plainTextBytes);
        cipher.init(Cipher.DECRYPT_MODE,normalKeyPair.getPrivate());
        byte[] res = cipher.doFinal(encRes);
        assertArrayEquals(res, plainTextBytes);
    }

    public static void testEncKey(byte[] plainTextBytes) throws Exception {
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(true);
        Assert.assertTrue(encKeyPair.getPrivate() instanceof SDFECPrivateKeyImpl);
        byte[] encryptedData = SDFSM2TestUtil.encrypt(encKeyPair.getPublic(), plainTextBytes);
        byte[] decryptedData = SDFSM2TestUtil.decrypt(encKeyPair.getPrivate(), encryptedData);
        assertArrayEquals(plainTextBytes, decryptedData);
    }
}
