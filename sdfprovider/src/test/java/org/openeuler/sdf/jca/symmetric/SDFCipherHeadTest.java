/*
 * Copyright (c) 2025, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.sdf.jca.symmetric;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;
import java.util.Arrays;

public class SDFCipherHeadTest extends SDFSymmetricTest {
    private static final byte[] CIPHER_HEAD = "HSMCipher".getBytes();

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testDoFinal() throws Exception {
        SecretKey secretKey = SDFSymmetricTestUtil.generateKey("SM4", null, 128, true);
        String algorithm = "SM4/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algorithm);
        byte[] plainData = "abcdefghijklmnop".getBytes();

        SDFIvParameterSpec sdfIvSpec = new SDFIvParameterSpec(new byte[16], true);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, sdfIvSpec);
        byte[] encData = cipher.doFinal(plainData);
        // encrypt with cipher head, then decrypt success
        cipher.init(Cipher.DECRYPT_MODE, secretKey, sdfIvSpec);
        byte[] decData = cipher.doFinal(encData);
        Assert.assertArrayEquals(plainData, decData);

        // encrypt with cipher head, then remove head and decrypt success
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decData2 = cipher.doFinal(Arrays.copyOfRange(encData, CIPHER_HEAD.length, encData.length));
        Assert.assertArrayEquals(plainData, decData2);

        // encrypt no cipher head, then add cipher head and decrypt success
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encWithoutHead = cipher.doFinal(plainData);
        byte[] addCipherHead = new byte[encWithoutHead.length + CIPHER_HEAD.length];
        System.arraycopy(CIPHER_HEAD, 0, addCipherHead, 0, CIPHER_HEAD.length);
        System.arraycopy(encWithoutHead, 0, addCipherHead, CIPHER_HEAD.length, encWithoutHead.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, sdfIvSpec);
        byte[] decWithAddHead = cipher.doFinal(addCipherHead);
        Assert.assertArrayEquals(plainData, decWithAddHead);
    }
}
