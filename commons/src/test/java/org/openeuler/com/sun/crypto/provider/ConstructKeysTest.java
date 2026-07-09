/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
package org.openeuler.com.sun.crypto.provider;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.*;

public class ConstructKeysTest {

    @Test
    public void constructorCreatesInstance() {
        assertNotNull(new ConstructKeys());
    }

    @Test
    public void constructsSecretPublicAndPrivateKeys() throws Exception {
        byte[] secret = new byte[]{1, 2, 3, 4};
        Key secretKey = ConstructKeys.constructKey(secret, "AES", Cipher.SECRET_KEY);
        assertTrue(secretKey instanceof SecretKey);
        assertEquals("AES", secretKey.getAlgorithm());
        assertArrayEquals(secret, secretKey.getEncoded());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512);
        KeyPair keyPair = generator.generateKeyPair();

        PublicKey publicKey = ConstructKeys.constructPublicKey(keyPair.getPublic().getEncoded(), "RSA");
        assertEquals(keyPair.getPublic(), publicKey);
        assertEquals(publicKey, ConstructKeys.constructKey(keyPair.getPublic().getEncoded(), "RSA", Cipher.PUBLIC_KEY));

        PrivateKey privateKey = ConstructKeys.constructPrivateKey(keyPair.getPrivate().getEncoded(), "RSA");
        assertEquals(keyPair.getPrivate(), privateKey);
        assertEquals(privateKey, ConstructKeys.constructKey(keyPair.getPrivate().getEncoded(), "RSA", Cipher.PRIVATE_KEY));

        assertNull(ConstructKeys.constructKey(secret, "AES", -1));
    }

    @Test
    public void wrapsInvalidEncodedKeysInInvalidKeyException() throws Exception {
        try {
            ConstructKeys.constructPublicKey(new byte[]{1}, "RSA");
            fail("expected InvalidKeyException");
        } catch (InvalidKeyException expected) {
            assertNotNull(expected.getCause());
        }

        try {
            ConstructKeys.constructPrivateKey(new byte[]{1}, "RSA");
            fail("expected InvalidKeyException");
        } catch (InvalidKeyException expected) {
            assertNotNull(expected.getCause());
        }
    }

    @Test
    public void reportsUnknownAlgorithms() throws Exception {
        try {
            ConstructKeys.constructPublicKey(new byte[]{1}, "NoSuchAlgorithmForTest");
            fail("expected NoSuchAlgorithmException");
        } catch (NoSuchAlgorithmException expected) {
            assertTrue(expected.getMessage().contains("NoSuchAlgorithmForTest"));
        }

        try {
            ConstructKeys.constructPrivateKey(new byte[]{1}, "NoSuchAlgorithmForTest");
            fail("expected NoSuchAlgorithmException");
        } catch (NoSuchAlgorithmException expected) {
            assertTrue(expected.getMessage().contains("NoSuchAlgorithmForTest"));
        }
    }
}
