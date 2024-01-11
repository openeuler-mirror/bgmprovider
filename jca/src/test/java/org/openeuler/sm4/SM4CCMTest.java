/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sm4;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;

public class SM4CCMTest {

    // Valid tag size
    private static final int[] validTagSizes = new int[]{4, 6, 8, 10, 12, 14, 16};

    // Invalid tag size
    private static final int[] invalidTagSizes = new int[]{0, 1, 2, 3, 5, 7, 9, 11, 13, 15, 17, 18, 100};
    // Initialization Vector
    private static final byte[] IV = toBytes("00001234567800000000ABCD");
    // Key
    private static final byte[] KEY = toBytes("0123456789ABCDEFFEDCBA9876543210");
    // Plaintext
    private static final byte[] PLAIN_TEXT = toBytes(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB" +
                    "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" +
                    "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF" +
                    "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
    // Associated Data
    private static final byte[] AAD = toBytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");

    // CipherText
    private static final byte[] CIPHER_TEXT = toBytes(
            "48AF93501FA62ADBCD414CCE6034D895" +
                    "DDA1BF8F132F042098661572E7483094" +
                    "FD12E518CE062C98ACEE28D95DF4416B" +
                    "ED31A2F04476C18BB40C84A74B97DC5B");

    // Authentication Tag
    private static final byte[] AUTH_TAG = toBytes("16842D4FA186F56AB33256971FA110F4");

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void testGCMParameterSpec() throws Exception {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "SM4");
        Cipher cipher = Cipher.getInstance("SM4/CCM/NoPadding");

        // test valid tag size
        for (int validTagSize : validTagSizes) {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(validTagSize * 8, new byte[12]);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        }

        // test  invalid tag size
        for (int invalidTagSize : invalidTagSizes) {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(invalidTagSize * 8, new byte[12]);
            Exception expectedException = null;
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                expectedException = e;
            }
            Assert.assertTrue(expectedException instanceof InvalidAlgorithmParameterException);
        }
    }

    @Test
    public void testEncrypt() throws Exception {
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec ivParameterSpec = new GCMParameterSpec(AUTH_TAG.length * 8, IV);
        Cipher cipher = Cipher.getInstance("SM4/CCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        cipher.updateAAD(AAD);
        byte[] encryptedBytes = cipher.doFinal(PLAIN_TEXT);

        // test length
        Assert.assertEquals(CIPHER_TEXT.length + AUTH_TAG.length, encryptedBytes.length);

        // test cipher text
        byte[] actualCipherText = new byte[CIPHER_TEXT.length];
        System.arraycopy(encryptedBytes, 0, actualCipherText, 0, actualCipherText.length);
        Assert.assertArrayEquals(CIPHER_TEXT, actualCipherText);

        // test authentication tag
        byte[] actualAuthTag = new byte[AUTH_TAG.length];
        System.arraycopy(encryptedBytes, CIPHER_TEXT.length, actualAuthTag, 0, actualAuthTag.length);
        Assert.assertArrayEquals(AUTH_TAG, actualAuthTag);
    }

    @Test
    public void testDecrypt() throws Exception {
        byte[] encryptedBytes = new byte[CIPHER_TEXT.length + AUTH_TAG.length];
        System.arraycopy(CIPHER_TEXT, 0, encryptedBytes, 0, CIPHER_TEXT.length);
        System.arraycopy(AUTH_TAG, 0, encryptedBytes, CIPHER_TEXT.length, AUTH_TAG.length);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec ivParameterSpec = new GCMParameterSpec(AUTH_TAG.length * 8, IV);
        Cipher cipher = Cipher.getInstance("SM4/CCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        cipher.updateAAD(AAD);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        Assert.assertArrayEquals(PLAIN_TEXT, decryptedBytes);
    }

    private static byte[] toBytes(String str) {
        int length = str.length();
        char[] charArray = str.toCharArray();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) Short.parseShort(
                    charArray[i] + "" + charArray[i + 1], 16);
        }
        return bytes;
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte aByte : bytes) {
            builder.append(Integer.toHexString(aByte & 0xFF));
        }
        return builder.toString().toUpperCase();
    }
}
