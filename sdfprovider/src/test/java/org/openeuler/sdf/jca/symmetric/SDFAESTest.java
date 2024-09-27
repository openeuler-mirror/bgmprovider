/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.commons.util.SDFTestUtil;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * @test
 * @summary Basic test for AES
 * @run main AESTest
 */

@Ignore
public class SDFAESTest {
    private static final String[] ALGORITHMS = {"AES", "AES_128", "AES_192", "AES_256"};
    private static final String[] MODES = {"ECB", "CBC"};
    private static final String[] PADDINGS = {"NoPadding", "PKCS5Padding"};
    private static final int AES_128_KEY_LENGTH = 128;
    private static final int AES_192_KEY_LENGTH = 192;
    private static final int AES_256_KEY_LENGTH = 256;
    private static String plainText = "helloworldhellow"; // 16bytes for NoPadding
    private static String shortPlainText = "helloworld"; // 5 bytes for padding

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void test() throws Exception {
        for (String algo : ALGORITHMS) {
            for (String mode : MODES) {
                for (String padding : PADDINGS) {
                    System.out.println("TEST:" + algo + "/" + mode + "/" + padding);
                    testAES(algo, mode, padding, true);
                }
            }
        }
    }

    private static void testAES(String algo, String mo, String pad, boolean isEncKey) throws Exception {
        AlgorithmParameterSpec aps = null;

        Cipher cipher = Cipher.getInstance(algo + "/" + mo + "/" + pad);
        SecretKey key = isEncKey ? getEncSecretKey(algo) : getNormalSecretKey(algo);

        // encrypt
        if (!mo.equalsIgnoreCase("GCM")) {
            cipher.init(Cipher.ENCRYPT_MODE, key, aps);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        String cipherString = null;
        if (!pad.equalsIgnoreCase("NoPadding")) {
            cipherString = shortPlainText;
        } else {
            cipherString = plainText;
        }
        byte[] cipherText = cipher.doFinal(cipherString.getBytes(StandardCharsets.UTF_8));
        if (!mo.equalsIgnoreCase("ECB")) {
            aps = new IvParameterSpec(cipher.getIV());
        } else {
            aps = null;
        }

        if (!mo.equalsIgnoreCase("GCM")) {
            cipher.init(Cipher.DECRYPT_MODE, key, aps);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        }

        String decryptPlainText = new String(cipher.doFinal(cipherText));

        if (!cipherString.equals(decryptPlainText)) {
            throw new RuntimeException("aes decryption failed, algo = " + algo + ", mo = " + mo + ", pad = " + pad);
        }
    }

    private static SecretKey getEncSecretKey(String algo) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SDFKeyGeneratorParameterSpec parameterSpec;

        if (algo.equalsIgnoreCase("AES_192")) {
            parameterSpec = new SDFKeyGeneratorParameterSpec(SDFTestUtil.getTestKekId(),
                    SDFTestUtil.getTestRegionId(), SDFTestUtil.getTestCdpId(), SDFTestUtil.getTestPin(), AES_192_KEY_LENGTH);
        } else if (algo.equalsIgnoreCase("AES_256")) {
            parameterSpec = new SDFKeyGeneratorParameterSpec(SDFTestUtil.getTestKekId(),
                    SDFTestUtil.getTestRegionId(), SDFTestUtil.getTestCdpId(), SDFTestUtil.getTestPin(), AES_256_KEY_LENGTH);
        } else {
            parameterSpec = new SDFKeyGeneratorParameterSpec(SDFTestUtil.getTestKekId(),
                    SDFTestUtil.getTestRegionId(), SDFTestUtil.getTestCdpId(), SDFTestUtil.getTestPin(), AES_128_KEY_LENGTH);
        }
        kg.init(parameterSpec);
        return kg.generateKey();
    }

    private static SecretKey getNormalSecretKey(String algo) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SDFKeyGeneratorParameterSpec parameterSpec;
        if (algo.equalsIgnoreCase("AES_192")) {
            kg.init(AES_192_KEY_LENGTH);
        } else if (algo.equalsIgnoreCase("AES_256")) {
            kg.init(AES_256_KEY_LENGTH);
        } else {
            kg.init(AES_128_KEY_LENGTH);
        }
        return kg.generateKey();
    }
}
