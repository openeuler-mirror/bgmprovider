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
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;


public class SDFRSACipherTest {
    private static final int[] KEY_SIZES = {1024, 2048, 3072, 4096};
    private static final String[] TRANSFORMATIONS = {
            "RSA/ECB/NoPadding",
            "RSA/ECB/PKCS1Padding",
            "RSA/ECB/OAEPPadding",
            "RSA/ECB/OAEPWithMD5AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA1AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-224AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-384AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-512/224AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-512/256AndMGF1Padding",
    };

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        if (!SDFTestUtil.isEnableNonSM()) {
            System.out.println("skip test case testEncryptAndDecrypt");
            return;
        }
        for (String transformation : TRANSFORMATIONS) {
            test(transformation);
        }
    }

    private static void test(String transformation) throws Exception {
        for (int keySize : KEY_SIZES) {
            System.out.println("Test transformation=" + transformation + ", keySize=" + keySize);
            KeyPair keyPair = SDFRSATestUtil.generateKeyPair(keySize, "SDFProvider");
            testEncryptAndDecrypt(transformation, keyPair.getPrivate(), keyPair.getPublic(), keySize);
        }
    }

    private static void testEncryptAndDecrypt(String transformation, PrivateKey privateKey,
                                              PublicKey publicKey, int keySize)
            throws Exception {
        int keyByteLen = keySize >> 3;
        byte[] randomMsg = generateMsg(transformation, keyByteLen);
        if (randomMsg == null) {
            System.out.println("Skip test, Key is too short for encryption using " + transformation);
            return;
        }
        byte[] jdkEncBytes = SDFRSATestUtil.encrypt(transformation, "SunJCE", publicKey, randomMsg);
        byte[] sdfEncBytes = SDFRSATestUtil.encrypt(transformation, "SDFProvider", publicKey, randomMsg);
        if (isNoPadding(transformation)) {
            Assert.assertArrayEquals(jdkEncBytes, sdfEncBytes);
        }

        byte[] jdkDecBytes = SDFRSATestUtil.decrypt(transformation, "SunJCE", privateKey, sdfEncBytes);
        byte[] sdfDecBytes = SDFRSATestUtil.decrypt(transformation, "SDFProvider", privateKey, sdfEncBytes);
        Assert.assertArrayEquals(jdkDecBytes, sdfDecBytes);
        if (isNoPadding(transformation)) {
            randomMsg = padZero(randomMsg, keyByteLen);
        }
        Assert.assertArrayEquals(randomMsg, sdfDecBytes);
    }

    private static boolean isNoPadding(String transformation) {
        return transformation.toUpperCase().contains("NOPADDING");
    }

    private static boolean isPKCS1Padding(String transformation) {
        return transformation.toUpperCase().contains("PKCS1PADDING");
    }

    private static boolean isOAEPPadding(String transformation) {
        transformation = transformation.toUpperCase();
        return transformation.contains("OAEPPADDING") || transformation.contains("OAEPWITH");
    }

    private static int getDigestLen(String transformation) {
        transformation = transformation.toUpperCase();
        if (!isOAEPPadding(transformation)) {
            return 0;
        }
        if (transformation.contains("MD5")) {
            return 16;
        } else if (transformation.contains("SHA1") || transformation.contains("SHA-1")) {
            return 20;
        } else if (transformation.contains("SHA-224")) {
            return 28;
        } else if (transformation.contains("SHA-256")) {
            return 32;
        } else if (transformation.contains("SHA-384")) {
            return 48;
        } else if (transformation.contains("SHA-512/224")) {
            return 28;
        } else if (transformation.contains("SHA-512/256")) {
            return 32;
        } else if (transformation.contains("SHA-512")) {
            return 64;
        } else { // default SHA-1
            return 20;
        }
    }

    private static byte[] generateMsg(String transformation, int keyByteLen) {
        int bounds = 0;
        if (isNoPadding(transformation)) {
            bounds = keyByteLen;
        } else if (isPKCS1Padding(transformation)) {
            bounds = keyByteLen - 11;
        } else if (isOAEPPadding(transformation)) {
            bounds = keyByteLen - 2 - 2 * getDigestLen(transformation);
        }
        if (bounds <= 0) {
            return null;
        }
        return SDFTestUtil.generateRandomBytesByBound(bounds);
    }

    private static byte[] padZero(byte[] bytes, int len) {
        if (bytes.length == len) {
            return bytes;
        }
        byte[] padZeroBytes = new byte[len];
        System.arraycopy(bytes, 0, padZeroBytes, padZeroBytes.length - bytes.length, bytes.length);
        return padZeroBytes;
    }
}
