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

package org.openeuler.sdf.jca.pbkdf2;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Provider;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class SDFPBKDF2Test extends SDFTestCase {
    private static final Provider sdfProvider = new SDFProvider();
    private static final Provider bgmJCEProvider = new BGMJCEProvider();
    private static final String[] algorithms =
            SDFTestUtil.isEnableNonSM() ? new String[]{
                    "PBKDF2WithHmacSM3",
                    "PBKDF2WithHmacSHA1",
                    "PBKDF2WithHmacSHA224",
                    "PBKDF2WithHmacSHA256",
                    "PBKDF2WithHmacSHA384",
//                    "PBKDF2WithHmacSHA512"
    } :
                    new String[]{"PBKDF2WithHmacSM3"};
    private static final char[] PASSWORD = "password".toCharArray();
    private static final byte[] SALT = "salt".getBytes();
    private static final int ITERATION_COUNT = 10000;
    private static final int KEY_LEN = 256;

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(bgmJCEProvider, 2);
    }

    @Test
    public void generateSecretPasswordTest() throws Exception {
        int[] passwdLens = new int[]{1, 2, 3, 9, 10, 100, 200, 500};
        for (int passwdLen : passwdLens) {
            char[] password = new String(SDFTestUtil.generateRandomBytes(passwdLen)).toCharArray();
            generateSecretTest(algorithms, password, SALT, ITERATION_COUNT, KEY_LEN);
        }
    }

    @Test
    public void generateSecretSaltTest() throws Exception {
        // Arg: salt length need: 1 <= saltLen <= 60
        int[] saltLens = new int[]{1, 2, 3, 9, 10, 20, 50, 60};
        for (int saltLen : saltLens) {
            byte[] salt = SDFTestUtil.generateRandomBytes(saltLen);
            generateSecretTest(algorithms, PASSWORD, salt, ITERATION_COUNT, KEY_LEN);
        }
    }

    @Test
    public void generateSecretIterationCountTest() throws Exception {
        int[] iterationCounts = new int[]{1, 2, 3, 9, 10, 100, 200, 500, 1000, 5000, 10000};
        for (int iterationCount : iterationCounts) {
            generateSecretTest(algorithms, PASSWORD, SALT, iterationCount, KEY_LEN);
        }
    }

    @Test
    public void generateSecretKeyLenTest() throws Exception {
        // Arg: keyLen need: 14 <= keyLen <= 64
        int[] keyLens = new int[]{112, 128, 256, 512};
        for (int keyLen : keyLens) {
            generateSecretTest(algorithms, PASSWORD, SALT, ITERATION_COUNT, keyLen);
        }
    }

    @Test
    public void generateSecretRandomlyTest() throws Exception {
        generateSecretRandomlyTest(algorithms);
    }

    @Test
    public void getAlgorithmAndFormatTest() throws Exception {
        getAlgorithmAndFormatTest(algorithms);
    }

    @Test
    public void getKeySpecTest() throws Exception {
        getKeySpecTest(algorithms);
    }

    public void getKeySpecTest(String[] algorithms) throws Exception {
        for (String algorithm : algorithms) {
            System.out.println("algorithm=" + algorithm);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            SecretKey secretKey = secretKeyFactory.generateSecret(
                    new PBEKeySpec(PASSWORD, SALT, ITERATION_COUNT, KEY_LEN));
            KeySpec keySpec = secretKeyFactory.getKeySpec(secretKey, PBEKeySpec.class);
            Assert.assertTrue(keySpec instanceof PBEKeySpec);
            PBEKeySpec pbeKeySpec = (PBEKeySpec) keySpec;
            Assert.assertArrayEquals(PASSWORD, pbeKeySpec.getPassword());
            Assert.assertArrayEquals(SALT, pbeKeySpec.getSalt());
            Assert.assertEquals(ITERATION_COUNT, pbeKeySpec.getIterationCount());
            Assert.assertEquals(KEY_LEN, pbeKeySpec.getKeyLength());
            System.out.println("----------------------------------------------------");
        }
    }

    private static void getAlgorithmAndFormatTest(String[] algorithms) throws Exception {
        for (String algorithm : algorithms) {
            System.out.println("algorithm=" + algorithm);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            SecretKey secretKey = secretKeyFactory.generateSecret(
                    new PBEKeySpec(PASSWORD, SALT, ITERATION_COUNT, KEY_LEN));
            Assert.assertEquals(algorithm, secretKey.getAlgorithm());
            Assert.assertEquals("RAW", secretKey.getFormat());
            System.out.println("----------------------------------------------------");
        }
    }

    private static void generateSecretRandomlyTest(String[] algorithms) throws Exception {
        for (String algorithm : algorithms) {
            generateSecretRandomlyTest(algorithm);
        }
    }

    private static void generateSecretRandomlyTest(String algorithm) throws Exception {
        char[] password = new String(SDFTestUtil.generateRandomBytes()).toCharArray();
        byte[] salt = SDFTestUtil.generateRandomBytes(60);
        int iterationCount = SDFTestUtil.generateRandomInt();
        int keyLen = SDFTestUtil.generateRandomInt(400) + 112;
        generateSecretTest(algorithm, password, salt, iterationCount, keyLen);
    }

    private static void generateSecretTest(String[] algorithms,char[] password,
                                           byte[] salt, int iterationCount, int keyLen) throws Exception {
        for(String algorithm : algorithms) {
            generateSecretTest(algorithm, password, salt, iterationCount, keyLen);
        }
    }

    private static void generateSecretTest(String algorithm, char[] password,
                                           byte[] salt, int iterationCount, int keyLen) throws Exception {
        System.out.println("algorithm=" + algorithm);
        System.out.println("password=" + Arrays.toString(password));
        System.out.println("salt=" + Arrays.toString(salt));
        System.out.println("iterationCount=" + iterationCount);
        System.out.println("keyLen=" + keyLen);
        byte[] baseLineKeyBytes = generateSecret(algorithm, null, password, salt, iterationCount, keyLen);
        byte[] sdfKeyBytes = generateSecret(algorithm, sdfProvider, password, salt, iterationCount, keyLen);
        System.out.println("baseLineKeyBytes=" + Arrays.toString(baseLineKeyBytes));
        System.out.println("sdfKeyBytes=" + Arrays.toString(sdfKeyBytes));
        Assert.assertArrayEquals(baseLineKeyBytes, sdfKeyBytes);
        System.out.println("----------------------------------------------------");
    }

    private static byte[] generateSecret(String algorithm, Provider provider,
                                         char[] password, byte[] salt, int iterationCount, int keyLen)
            throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount, keyLen);
        SecretKeyFactory secretKeyFactory;
        if (provider != null) {
            secretKeyFactory = SecretKeyFactory.getInstance(algorithm, provider);
        } else {
            secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        }
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        return secretKey.getEncoded();
    }
}
