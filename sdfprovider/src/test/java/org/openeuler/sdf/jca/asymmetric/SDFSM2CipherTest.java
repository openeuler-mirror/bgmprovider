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
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SDFSM2CipherTest extends SDFTestCase {

    private static final Provider sdfProvider = new SDFProvider();
    private static final Provider bgmJCEProvider = new BGMJCEProvider();

    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(sdfProvider, 1);
    }

    @Test
    public void testEncAndDecRandomly() throws Exception {
        byte[] data = SDFTestUtil.generateRandomBytes();
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(true);
        Assert.assertTrue(encKeyPair.getPrivate() instanceof SDFECPrivateKeyImpl);
        byte[] encryptedData = SDFSM2TestUtil.encrypt(encKeyPair.getPublic(), data);
        byte[] decryptedData = SDFSM2TestUtil.decrypt(encKeyPair.getPrivate(), encryptedData);
        assertArrayEquals(data, decryptedData);
    }

    @Test
    public void testEncAndDecSample() throws Exception {
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(true);
        Assert.assertTrue(encKeyPair.getPrivate() instanceof SDFECPrivateKeyImpl);

        int[] sizes = {1, 8, 16, 33, 132, 160, 200};
        for (int size : sizes) {
            byte[] data = SDFTestUtil.generateRandomBytes(size);
            System.out.println("TEST data=" + Arrays.toString(data));
            byte[] encryptedData = SDFSM2TestUtil.encrypt(encKeyPair.getPublic(), data);
            byte[] decryptedData = SDFSM2TestUtil.decrypt(encKeyPair.getPrivate(), encryptedData);
            assertArrayEquals(data, decryptedData);
        }
    }

    @Test
    public void testEncAndDecEmpty() throws Exception {
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(true);
        Assert.assertTrue(encKeyPair.getPrivate() instanceof SDFECPrivateKeyImpl);
        byte[] data = new byte[0];
        Exception exception = null;
        try {
            SDFSM2TestUtil.encrypt(encKeyPair.getPublic(), data);
        } catch (Exception e) {
            exception = e;
        }
        Assert.assertTrue(exception instanceof IllegalArgumentException);

        byte[] encryptedData = new byte[0];
        try {
            SDFSM2TestUtil.decrypt(encKeyPair.getPrivate(), encryptedData);
        } catch (Exception e) {
            exception = e;
        }
        Assert.assertTrue(exception instanceof IllegalArgumentException);
    }

    @Test
    public void testEncByBGMJCEProviderDecBySDFProvider() throws Exception {
        byte[] data = SDFTestUtil.generateRandomBytes();
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(true);
        byte[] encryptedData = SDFSM2TestUtil.encrypt(bgmJCEProvider, encKeyPair.getPublic(), data);
        byte[] decryptedData = SDFSM2TestUtil.decrypt(sdfProvider, encKeyPair.getPrivate(), encryptedData);
        assertArrayEquals(data, decryptedData);
    }

    @Test
    public void testEncBySDFProviderDecByBGMJCEProvider() throws Exception {
        Provider bgmJCEProvider = new BGMJCEProvider();
        byte[] data = SDFTestUtil.generateRandomBytes();
        KeyPair encKeyPair = SDFSM2TestUtil.generateKeyPair(false, bgmJCEProvider);
        byte[] encryptedData = SDFSM2TestUtil.encrypt(sdfProvider, encKeyPair.getPublic(), data);
        byte[] decryptedData = SDFSM2TestUtil.decrypt(bgmJCEProvider, encKeyPair.getPrivate(), encryptedData);
        assertArrayEquals(data, decryptedData);
    }

    @Test
    public void testWrapAndUnwrap()
            throws Exception {
        KeyPair keyPair = SDFSM2TestUtil.generateKeyPair(true);
        KeyPair wrapKeyPair = SDFSM2TestUtil.generateKeyPair(true);
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
        assertEquals("SM2 Cipher not initialised from SDFProvider",
                "SDFProvider", cipher.getProvider().getName());
        byte[] wrappedKeyBytes = cipher.wrap(wrapKeyPair.getPublic());
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
        Key unWrappedKey = cipher.unwrap(wrappedKeyBytes, "SM2", Cipher.PUBLIC_KEY);
        assertArrayEquals(wrapKeyPair.getPublic().getEncoded(), unWrappedKey.getEncoded());
    }
}
