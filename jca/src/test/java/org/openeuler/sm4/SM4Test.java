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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * SM4 full test
 */
public class SM4Test {
    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        try {
            Class<?> clazz = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider bcProvider = (Provider) clazz.newInstance();
            Security.insertProviderAt(bcProvider, 2);
        } catch (Exception e) {
            System.err.println("BouncyCastleProvider does not exist");
        }
    }

    @Test
    public void testSaveAndRestore() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        key = new SecretKeySpec(new byte[16], "SM4");

        testSaveAndRestore("SM4/CBC/NoPadding", key, 16, 48);
        testSaveAndRestore("SM4/CFB/NoPadding", key, 16, 52);
        testSaveAndRestore("SM4/OFB/NoPadding", key, 16, 53);
        testSaveAndRestore("SM4/CTS/NoPadding", key, 16, 54);
        testSaveAndRestore("SM4/CTR/NoPadding", key, 16, 55);
        testSaveAndRestore("SM4/GCM/NoPadding", key, 12, 56);
        testSaveAndRestore("SM4/OCB/NoPadding", key, 12, 57);
        testSaveAndRestore("SM4/CCM/NoPadding", key, 12, 58);

        testSaveAndRestore("SM4/CBC/PKCS5Padding", key, 16, 48);
        testSaveAndRestore("SM4/CFB/PKCS5Padding", key, 16, 52);
        testSaveAndRestore("SM4/OFB/PKCS5Padding", key, 16, 53);
        testSaveAndRestore("SM4/CTR/PKCS5Padding", key, 16, 54);
    }

    private void testSaveAndRestore(String transformation, Key key, int ivLen, int plainTextLen) throws Exception {
        // compute expect encrypted bytes
        byte[] iv = new byte[ivLen];
        AlgorithmParameterSpec parameterSpec = new IvParameterSpec(iv);
        byte[] plainText = new byte[plainTextLen];
        Arrays.fill(plainText, (byte) 1);
        Cipher cipher = Cipher.getInstance(transformation, "BGMJCEProvider");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText);

        // compute actual encrypted bytes
        // decrypt update
        cipher = Cipher.getInstance(transformation, "BGMJCEProvider");
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        int updateLen = encryptedBytes.length / 2;
        byte[] updatedDecryptedBytes = cipher.update(encryptedBytes, 0, updateLen);
        if (updatedDecryptedBytes == null) {
            updatedDecryptedBytes = new byte[0];
        }
        byte[] actualDecryptedBytes = Arrays.copyOf(updatedDecryptedBytes, updatedDecryptedBytes.length);

        // decrypt doFinal
        int doFinalLen = encryptedBytes.length - updateLen;
        int outputSize = cipher.getOutputSize(doFinalLen);
        byte[] output = new byte[outputSize];
        try {
            cipher.doFinal(encryptedBytes, updateLen, doFinalLen, output, 17);
        } catch (ShortBufferException e) {
            int decryptedFinalLen = cipher.doFinal(encryptedBytes, updateLen, doFinalLen, output, 0);
            actualDecryptedBytes = Arrays.copyOf(actualDecryptedBytes,
                    actualDecryptedBytes.length + decryptedFinalLen);
            System.arraycopy(output, 0, actualDecryptedBytes, updatedDecryptedBytes.length, decryptedFinalLen);
        }
        Assert.assertArrayEquals(plainText, actualDecryptedBytes);
    }

    @Test
    public void testUpdateAndDoFinalZeroParameter() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        // SM4/GCM/NoPadding
        // SM4/CCM/NoPadding
        int[] lengthArray = {0,15, 16, 17, 32, 64, 105};
        for (int len : lengthArray) {
            testUpdateAndDoFinalZeroParameter("SM4/GCM/NoPadding", key, 12, len);
            testUpdateAndDoFinalZeroParameter("SM4/CTR/NoPadding", key, 12, len);
            testUpdateAndDoFinalZeroParameter("SM4/CCM/NoPadding", key, 12, len);
            testUpdateAndDoFinalZeroParameter("SM4/GCM/NoPadding", key, 12, len, 2);
            testUpdateAndDoFinalZeroParameter("SM4/CTR/NoPadding", key, 12, len, 2);
            testUpdateAndDoFinalZeroParameter("SM4/CCM/NoPadding", key, 12, len, 2);
        }

        // SM4/CTS/NoPadding
        lengthArray = new int[]{16, 17, 32, 105};
        for (int len : lengthArray) {
            testUpdateAndDoFinalZeroParameter("SM4/CTS/NoPadding", key, 16, len);
            testUpdateAndDoFinalZeroParameter("SM4/CTS/NoPadding", key, 16, len, 2);
        }

        // SM4/ECB/NoPadding
        // SM4/CBC/NoPadding
        // SM4/CFB/NoPadding
        // SM4/OFB/NoPadding
        // SM4/OCB/NoPadding
        lengthArray = new int[]{0, 16, 32, 64};
        for (int len : lengthArray) {
            testUpdateAndDoFinalZeroParameter("SM4/ECB/NoPadding", key, 16, len);
            testUpdateAndDoFinalZeroParameter("SM4/CBC/NoPadding", key, 16, len);
            testUpdateAndDoFinalZeroParameter("SM4/CFB/NoPadding", key, 16, len);
            testUpdateAndDoFinalZeroParameter("SM4/OFB/NoPadding", key, 16, len);
            testUpdateAndDoFinalZeroParameter("SM4/OCB/NoPadding", key, 12, len);

            testUpdateAndDoFinalZeroParameter("SM4/ECB/NoPadding", key, 16, len, 2);
            testUpdateAndDoFinalZeroParameter("SM4/CBC/NoPadding", key, 16, len, 2);
            testUpdateAndDoFinalZeroParameter("SM4/CFB/NoPadding", key, 16, len, 2);
            testUpdateAndDoFinalZeroParameter("SM4/OFB/NoPadding", key, 16, len, 2);
//            testUpdateAndDoFinalZeroParameter("SM4/OCB/NoPadding", key, 12, len, 2);
        }
    }

    private void testUpdateAndDoFinalZeroParameter(String transformation, Key key, int ivLen, int plainTextLen)
            throws Exception {
        testUpdateAndDoFinalZeroParameter(transformation, key, ivLen, plainTextLen, 1);
    }

    private void testUpdateAndDoFinalZeroParameter(String transformation, Key key, int ivLen, int plainTextLen,
                                                   int updateCount) throws Exception {

        SecureRandom random = new SecureRandom();

        byte[] plainTextBytes = new byte[plainTextLen];
        random.nextBytes(plainTextBytes);
        byte[] ivBytes = new byte[ivLen];
        random.nextBytes(ivBytes);
        AlgorithmParameterSpec params = null;
        byte[] aadBytes = null;

        if (transformation.contains("GCM")) {
            int tagSize = 16;
            params = new GCMParameterSpec(tagSize * 8, ivBytes);
            aadBytes = new byte[12];
            random.nextBytes(aadBytes);
        } else if (!transformation.contains("ECB")) {
            params = new IvParameterSpec(ivBytes);
        }

        Cipher bcCipher = Cipher.getInstance(transformation, "BC");
        bcCipher.init(Cipher.ENCRYPT_MODE, key, params, random);
        Cipher bgmCipher = Cipher.getInstance(transformation);
        bgmCipher.init(Cipher.ENCRYPT_MODE, key, params, random);

        if (aadBytes != null) {
            bcCipher.updateAAD(aadBytes);
            bgmCipher.updateAAD(aadBytes);
        }
        byte[] bcEncryptedBytesAll = null;
        byte[] bgmEncryptedBytesAll = null;

        for (int i = 0; i < updateCount; i++) {
            byte[] bcUpdateBytes = bcCipher.update(plainTextBytes);
            byte[] bgmUpdateBytes = bgmCipher.update(plainTextBytes);
            bcEncryptedBytesAll = concatBytes(bcEncryptedBytesAll, bcUpdateBytes);
            bgmEncryptedBytesAll = concatBytes(bgmEncryptedBytesAll, bgmUpdateBytes);
        }

        byte[] bcFinalBytes = bcCipher.doFinal();
        byte[] bgmFinalBytes = bgmCipher.doFinal();

        bcEncryptedBytesAll = concatBytes(bcEncryptedBytesAll, bcFinalBytes);
        bgmEncryptedBytesAll = concatBytes(bgmEncryptedBytesAll, bgmFinalBytes);

        Assert.assertArrayEquals(bcEncryptedBytesAll, bgmEncryptedBytesAll);
    }

    @Test
    public void testIvLengthAll() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        // no iv ECB

        // iv.length = 16 (CBC/CFB/CTS/OFB)
        String[] transformations = new String[]{
                "SM4/CBC/NoPadding",
                "SM4/CFB/NoPadding",
                "SM4/CTS/NoPadding",
                "SM4/OFB/NoPadding"
        };
        int[] validIvLengths = new int[]{16};
        int[] invalidIvLengths = new int[]{0, 7, 15, 17, 32};
        for (String transformation : transformations) {
            testIvLength(transformation, key, validIvLengths, invalidIvLengths);
        }

        // iv.length = [8,16] CTR
        validIvLengths = new int[9];
        for (int i = 0; i < validIvLengths.length; i++) {
            validIvLengths[i] = i + 8;
        }
        invalidIvLengths = new int[]{0, 1, 5, 7, 17, 32};
        testIvLength("SM4/CTR/NoPadding", key, validIvLengths, invalidIvLengths);

        // iv.length >=1 GCM
        validIvLengths = new int[32];
        for (int i = 0; i < validIvLengths.length; i++) {
            validIvLengths[i] = i + 1;
        }
        invalidIvLengths = new int[]{0};
        testIvLength("SM4/GCM/NoPadding", key, validIvLengths, invalidIvLengths);

        // iv.length = [0,15] OCB  RFC 7253 4.2. Nonce is a string of no more than 120 bits
        validIvLengths = new int[16];
        for (int i = 0; i < validIvLengths.length; i++) {
            validIvLengths[i] = i;
        }
        invalidIvLengths = new int[]{16, 17, 30};
        testIvLength("SM4/OCB/NoPadding", key, validIvLengths, invalidIvLengths);

        // iv.length = [7,13] CCM
        validIvLengths = new int[7];
        for (int i = 0; i < validIvLengths.length; i++) {
            validIvLengths[i] = i + 7;
        }
        testIvLength("SM4/CCM/NoPadding", key, validIvLengths, invalidIvLengths);
    }

    private void testIvLength(String transformation, Key key, int[] validIvLengths, int[] invalidIvLengths) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, "BGMJCEProvider");

        // valid iv
        for (int validIvLength : validIvLengths) {
            byte[] iv = new byte[validIvLength];
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }

        byte[] iv;
        for (int invalidIvLength : invalidIvLengths) {
            Throwable ex = null;
            try {
                iv = new byte[invalidIvLength];
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            } catch (Exception e) {
                ex = e;
            }
            Assert.assertTrue(transformation + " testIvLength " + invalidIvLength + " failed",
                    ex instanceof InvalidAlgorithmParameterException
                            || (ex != null && ex.getCause() != null &&
                            ex.getCause() instanceof ArrayIndexOutOfBoundsException));
        }
    }

    @Test
    public void testReDoFinalAll() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        int[] NoPaddingPlainTextLens = new int[]{16, 32};
        String[] NoPaddingTransformations = new String[]{
                "SM4/CBC/NoPadding",
                "SM4/CFB/NoPadding",
                "SM4/CTS/NoPadding",
                "SM4/CTR/NoPadding",
                "SM4/OFB/NoPadding"
        };

        int[] PKCS5PaddingPlainTextLens = new int[]{15, 16, 31, 32};
        String[] PKCS5PaddingTransformations = new String[]{
                "SM4/CBC/PKCS5Padding",
                "SM4/CFB/PKCS5Padding",
//                "SM4/CTS/PKCS5Padding",
                "SM4/CTR/PKCS5Padding",
                "SM4/OFB/PKCS5Padding"
        };

        // no iv ECB
        for (int plainTextLen : NoPaddingPlainTextLens) {
            testReDoFinal("SM4/ECB/NoPadding", key, 0, plainTextLen);
        }

        for (int plainTextLen : PKCS5PaddingPlainTextLens) {
            testReDoFinal("SM4/ECB/PKCS5Padding", key, 0, plainTextLen);
        }

        // iv.length = 16 (CBC/CFB/CTS/CTR/OFB)
        for (String transformation : NoPaddingTransformations) {
            for (int plainTextLen : NoPaddingPlainTextLens) {
                testReDoFinal(transformation, key, 16, plainTextLen);
            }
        }
        for (String transformation : PKCS5PaddingTransformations) {
            for (int plainTextLen : PKCS5PaddingPlainTextLens) {
                testReDoFinal(transformation, key, 16, plainTextLen);
            }
        }

        // iv.length = [8,16] CTR
        for (int i = 8; i <= 16; i++) {
            for (int plainTextLen : NoPaddingPlainTextLens) {
                testReDoFinal("SM4/CTR/NoPadding", key, i, plainTextLen);
            }

            for (int plainTextLen : PKCS5PaddingPlainTextLens) {
                testReDoFinal("SM4/CTR/PKCS5Padding", key, i, plainTextLen);
            }
        }

        // iv.length = [0,15]  OCB
        for (int i = 0; i <= 15; i++) {
            testReDoFinal("SM4/OCB/NoPadding", key, i, 16 * i);
        }

        // iv.length = [7,13]  CCM
        for (int i = 7; i <= 13; i++) {
            testReDoFinal("SM4/CCM/NoPadding", key, i, 16 * i);
        }

        // iv.length >=1 GCM
        for (int i = 1; i < 32; i++) {
            testReDoFinal("SM4/GCM/NoPadding", key, i, 16 * i);
        }
    }


    public void testReDoFinal(String transformation, Key key, int ivLen, int plainTextLen) throws Exception {
        SecureRandom random = new SecureRandom();

        // data
        byte[] data = new byte[plainTextLen];
        random.nextBytes(data);

        Cipher cipher = Cipher.getInstance(transformation, "BGMJCEProvider");
        Cipher bcCipher = Cipher.getInstance(transformation, "BC");
        IvParameterSpec ivParameterSpec = null;
        if (!transformation.contains("ECB")) {
            // iv
            byte[] iv = new byte[ivLen];
            random.nextBytes(iv);
            ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            bcCipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            bcCipher.init(Cipher.ENCRYPT_MODE, key);
        }

        byte[] encryptedBytes = cipher.doFinal(data);
        byte[] bcEncryptedBytes = bcCipher.doFinal(data);
        Assert.assertArrayEquals("transformation=" + transformation + ",ivLen=" + ivLen +
                        ",plainTextLen=" + plainTextLen, bcEncryptedBytes, encryptedBytes);
        Throwable ex = null;
        byte[] encryptedBytesAgain = null;
        byte[] bcEncryptedBytesAgain = null;
        try {
            encryptedBytesAgain = cipher.doFinal(data);
            bcEncryptedBytesAgain = bcCipher.doFinal(data);
        } catch (Exception e) {
            ex = e;
        }
        Assert.assertArrayEquals("transformation=" + transformation + ",ivLen=" + ivLen +
                ",plainTextLen=" + plainTextLen, bcEncryptedBytesAgain, encryptedBytesAgain);
        if (transformation.contains("GCM")) {
            Assert.assertTrue(transformation + " testReDoFinal encrypt failed",
                    ex instanceof IllegalStateException);
        } else {
            Assert.assertArrayEquals(transformation + " testReDoFinal encrypt failed",
                    encryptedBytes, encryptedBytesAgain);
        }

        if (!transformation.contains("ECB")) {
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        byte[] decryptedBytesAgain = cipher.doFinal(encryptedBytes);
        Assert.assertArrayEquals(transformation + " testReDoFinal decrypt failed",
                decryptedBytes, decryptedBytesAgain);
    }

    @Test
    public void testCCM() throws Exception {
        if (Security.getProvider("BC") == null) {
            System.out.println("Skip test, BouncyCastleProvider does not exist");
            return;
        }
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        int[] ivLens = new int[]{7, 8, 9, 10, 11, 12, 13};
        int[] lengths = new int[20];

        SecureRandom random = new SecureRandom();
        for (int i = 0; i < lengths.length; i++) {
            lengths[i] = random.nextInt(2048) + 1;
        }
        for (int ivLen : ivLens) {
            for (int length : lengths) {
                int tLen = (random.nextInt(6) + 2) * 2 * 8;
                testAEADMode("SM4/CCM/NoPadding", key, tLen, ivLen, length);
                int updateLen = random.nextInt(length);
                testUpdateAndDofinalAEADMode("SM4/CCM/NoPadding", key, tLen, ivLen, length, updateLen);
                testInitAlgorithmParameters("SM4/CCM/NoPadding", key, tLen, ivLen, length);
            }
        }
    }

    @Test
    public void testGetOutputSize() throws Exception {
        if (Security.getProvider("BC") == null) {
            System.out.println("Skip test, BouncyCastleProvider does not exist");
            return;
        }
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        int[] plainTextLens = {0, 10, 15, 16, 17, 31, 32, 33, 64, 128};
        String[] transformations = {
                "SM4/ECB/PKCS5Padding",
                "SM4/CBC/PKCS5Padding",
                "SM4/CFB/PKCS5Padding",
                "SM4/OFB/PKCS5Padding",
                "SM4/CTR/PKCS5Padding",
                "SM4/CTS/PKCS5Padding",

                "SM4/ECB/NoPadding",
                "SM4/CBC/NoPadding",
                "SM4/CFB/NoPadding",
                "SM4/OFB/NoPadding",
                "SM4/CTR/NoPadding",
                "SM4/CTS/NoPadding",

                "SM4/GCM/NoPadding",
                "SM4/CCM/NoPadding",
                "SM4/OCB/NoPadding"
        };
        for (int plainTextLen : plainTextLens) {
            for (String transformation : transformations) {
                testGetOutputSize(transformation, key, plainTextLen);
            }
        }
    }

    private void testGetOutputSize(String transformation, Key key, int plainTextLen)
            throws Exception {
        int tagLen = getTagLen(transformation);
        System.out.println("transformation=" + transformation + ", plainTextLen=" + plainTextLen + ", tagLen=" + tagLen);
        Cipher bcCipher = Cipher.getInstance(transformation, "BC");
        Cipher bgmCipher = Cipher.getInstance(transformation, "BGMJCEProvider");
        AlgorithmParameterSpec parameterSpec = getAlgorithmParameterSpec(transformation, tagLen);
        bcCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        bgmCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        int bcEncryptedOutputSize = bcCipher.getOutputSize(plainTextLen);
        int bgmEncryptedOutputSize = bgmCipher.getOutputSize(plainTextLen);
        System.out.println("bcEncryptedOutputSize:" + bcEncryptedOutputSize);
        System.out.println("bgmEncryptedOutputSize:" + bgmEncryptedOutputSize);
        Assert.assertEquals(bcEncryptedOutputSize, bgmEncryptedOutputSize);

        boolean isAADMode = isAADMode(transformation);
        boolean isPKCS5Padding = transformation.toUpperCase().contains("PKCS5");

        int expectedEncryptedLen = getExpectedOutputSize(isAADMode, isPKCS5Padding,
                plainTextLen, tagLen, false);
        Assert.assertEquals(expectedEncryptedLen, bgmEncryptedOutputSize);

        bcCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        bgmCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        int bcDecryptedOutputSize = bcCipher.getOutputSize(bcEncryptedOutputSize);
        int bgmDecryptedOutputSize = bgmCipher.getOutputSize(bgmEncryptedOutputSize);
        System.out.println("bcDecryptedOutputSize:" + bcDecryptedOutputSize);
        System.out.println("bgmDecryptedOutputSize:" + bgmDecryptedOutputSize);
        Assert.assertEquals(bcDecryptedOutputSize, bgmDecryptedOutputSize);

        int expectedDecryptedLen = getExpectedOutputSize(isAADMode, isPKCS5Padding,
                bgmEncryptedOutputSize, tagLen, true);
        Assert.assertEquals(expectedDecryptedLen, bgmDecryptedOutputSize);
    }

    private int getTagLen(String transformation) {
        transformation = transformation.toUpperCase();
        int[] supportedTagLens = null;
        if (transformation.contains("GCM")) { // 128, 120, 112, 104, 96
            supportedTagLens = new int[]{128, 120, 112, 104, 96};
        } else if (transformation.contains("CCM")) { // 128, 112, 96, 80, 64, 48, 32
            supportedTagLens = new int[]{128, 112, 96, 80, 64, 48, 32};
        } else if (transformation.contains("OCB")) { // 128
            supportedTagLens = new int[]{128, 120, 112, 104, 96, 88, 80, 72, 64};
        } else { // do nothing

        }
        if (supportedTagLens == null) {
            return 0;
        }
        SecureRandom random = new SecureRandom();
        int index = random.nextInt(supportedTagLens.length - 1);
        return supportedTagLens[index];
    }

    private int getExpectedOutputSize(boolean isAADMode, boolean isPKCS5Padding,
                                      int inputLen, int tagLen, boolean decrypting) {
        if (isAADMode) { // is AAD Mode (GCM/CCM/OCB)
            if (isPKCS5Padding) { // Not Support
                throw new IllegalStateException("Not Support");
            } else {
                int tLen = tagLen / 8;
                return decrypting ? inputLen - tLen : inputLen + tLen;
            }
        } else {
            if (isPKCS5Padding && !decrypting) {  // PKCS5Padding
                return inputLen + padLength(inputLen, 16);
            } else { // NoPadding
                return inputLen;
            }
        }
    }

    private int padLength(int len, int blockSize) {
        return blockSize - (len % blockSize);
    }

    private AlgorithmParameterSpec getAlgorithmParameterSpec(String transformation, int tagLen) {
        transformation = transformation.toUpperCase();
        if (transformation.contains("GCM")) {
            return new GCMParameterSpec(tagLen, new byte[12]);
        } else if (transformation.contains("CCM")) {
            return new GCMParameterSpec(tagLen, new byte[12]);
        } else if (transformation.contains("OCB")) {
            return new GCMParameterSpec(tagLen, new byte[15]);
        } else if (transformation.contains("ECB")) {
            return null;
        } else {
            return new IvParameterSpec(new byte[16]);
        }
    }

    private boolean isAADMode(String transformation) {
        transformation = transformation.toUpperCase();
        return transformation.contains("GCM") || transformation.contains("CCM") || transformation.contains("OCB");
    }

    @Test
    public void test() throws Exception {
        if (Security.getProvider("BC") == null) {
            System.out.println("Skip test, BouncyCastleProvider does not exist");
            return;
        }
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        // CBC
        int[] lengths = new int[]{0, 16, 32, 48, 64, 128};
        for (int length : lengths) {
            test("SM4/CBC/NoPadding", key, 16, length);
        }
        lengths = new int[]{0, 1, 3, 7, 15, 16, 17, 32, 33, 64, 128};
        for (int length : lengths) {
            test("SM4/CBC/PKCS5Padding", key, 16, length);
        }
        testUpdateAndDofinal("SM4/CBC/NoPadding", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CBC/NoPadding", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CBC/PKCS5Padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CBC/PKCS5Padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CBC/PKCS5Padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CBC/PKCS5Padding", key, 16, 32, 18);

        // CFB
        lengths = new int[]{0, 1, 3, 7, 15, 16, 17, 32, 33, 64, 128};
        for (int length : lengths) {
            test("SM4/CFB/NoPadding", key, 16, length);
            test("SM4/CFB/PKCS5Padding", key, 16, length);
        }
        testUpdateAndDofinal("SM4/CFB/NoPadding", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CFB/NoPadding", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CFB/PKCS5Padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CFB/PKCS5Padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CFB/PKCS5Padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CFB/PKCS5Padding", key, 16, 32, 18);

        // CTS
        lengths = new int[]{16, 32, 48, 64, 128};
        for (int length : lengths) {
            test("SM4/CTS/NoPadding", key, 16, length);
            //test("SM4/CTS/PKCS5Padding", key, 16, length);
        }
//        test("SM4/CTS/PKCS5Padding", key, 16, 32);
        testUpdateAndDofinal("SM4/CTS/NoPadding", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CTS/NoPadding", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CTS/PKCS5Padding", key, 16, 15, 6);
//        testUpdateAndDofinal("SM4/CTS/PKCS5Padding", key, 16, 31, 31);
//        testUpdateAndDofinal("SM4/CTS/PKCS5Padding", key, 16, 16, 16);
//        testUpdateAndDofinal("SM4/CTS/PKCS5Padding", key, 16, 32, 18);

        // CTR
        int[] ivLens = new int[]{8, 9, 10, 11, 12, 13, 14, 15, 16};
        lengths = new int[]{0, 1, 3, 7, 15, 16, 17, 32, 33, 64, 128};
        for (int ivLen : ivLens) {
            for (int length : lengths) {
                test("SM4/CTR/NoPadding", key, ivLen, length);
            }
        }
        testUpdateAndDofinal("SM4/CTR/NoPadding", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CTR/NoPadding", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CTR/NoPadding", key, 16, 15, 5);
        testUpdateAndDofinal("SM4/CTR/NoPadding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CTR/PKCS5Padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CTR/PKCS5Padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CTR/PKCS5Padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CTR/PKCS5Padding", key, 16, 32, 18);

        // OFB
        lengths = new int[]{0, 1, 3, 7, 15, 16, 17, 32, 33, 64, 128};
        for (int length : lengths) {
            test("SM4/OFB/NoPadding", key, 16, length);
            test("SM4/OFB/PKCS5Padding", key, 16, length);
        }
        testUpdateAndDofinal("SM4/OFB/NoPadding", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/OFB/NoPadding", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/OFB/PKCS5Padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/OFB/PKCS5Padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/OFB/PKCS5Padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/OFB/PKCS5Padding", key, 16, 32, 18);

        // ECB
        lengths = new int[]{0, 16, 32, 48, 64, 128};
        for (int length : lengths) {
            test("SM4/ECB/NoPadding", key, 0, length);
        }
        lengths = new int[]{0, 1, 3, 7, 15, 16, 17, 32, 33, 64, 128};
        for (int length : lengths) {
            test("SM4/ECB/PKCS5Padding", key, 0, length);
        }
        testUpdateAndDofinal("SM4/ECB/NoPadding", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/ECB/NoPadding", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/ECB/PKCS5Padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/ECB/PKCS5Padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/ECB/PKCS5Padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/ECB/PKCS5Padding", key, 16, 32, 18);

        // GCM
        testAEADMode("SM4/GCM/NoPadding", key, 96, 1, 16);
        testAEADMode("SM4/GCM/NoPadding", key, 104, 2, 17);
        testAEADMode("SM4/GCM/NoPadding", key, 112, 3, 18);
        testAEADMode("SM4/GCM/NoPadding", key, 120, 4, 19);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 5, 20);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 6, 21);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 7, 22);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 8, 23);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 9, 24);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 10, 25);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 11, 26);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 12, 27);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 13, 28);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 14, 29);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 15, 30);
        testAEADMode("SM4/GCM/NoPadding", key, 128, 16, 31);
        testUpdateAndDofinalAEADMode("SM4/GCM/NoPadding", key, 128, 16, 15, 6);
        testUpdateAndDofinalAEADMode("SM4/GCM/NoPadding", key, 128, 16, 31, 31);
        testUpdateAndDofinalAEADMode("SM4/GCM/NoPadding", key, 128, 16, 16, 16);
        testUpdateAndDofinalAEADMode("SM4/GCM/NoPadding", key, 128, 16, 32, 18);

        testAEADMode("SM4/OCB/NoPadding", key, 64, 0, 16);
        testAEADMode("SM4/OCB/NoPadding", key, 72, 1, 17);
        testAEADMode("SM4/OCB/NoPadding", key, 80, 2, 18);
        testAEADMode("SM4/OCB/NoPadding", key, 88, 3, 19);
        testAEADMode("SM4/OCB/NoPadding", key, 96, 4, 20);
        testAEADMode("SM4/OCB/NoPadding", key, 104, 5, 21);
        testAEADMode("SM4/OCB/NoPadding", key, 112, 6, 22);
        testAEADMode("SM4/OCB/NoPadding", key, 120, 7, 23);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 8, 24);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 9, 25);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 10, 26);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 11, 27);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 12, 28);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 13, 29);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 14, 30);
        testAEADMode("SM4/OCB/NoPadding", key, 128, 15, 31);
        testUpdateAndDofinalAEADMode("SM4/OCB/NoPadding", key, 128, 15, 15, 6);
        testUpdateAndDofinalAEADMode("SM4/OCB/NoPadding", key, 128, 15, 31, 31);
        testUpdateAndDofinalAEADMode("SM4/OCB/NoPadding", key, 128, 15, 16, 16);
        testUpdateAndDofinalAEADMode("SM4/OCB/NoPadding", key, 128, 15, 32, 18);

        testAEADMode("SM4/CCM/NoPadding", key, 96, 7, 16);
        testAEADMode("SM4/CCM/NoPadding", key, 96, 8, 16);
        testAEADMode("SM4/CCM/NoPadding", key, 96, 9, 16);
        testAEADMode("SM4/CCM/NoPadding", key, 96, 10, 16);
        testAEADMode("SM4/CCM/NoPadding", key, 96, 11, 16);
        testAEADMode("SM4/CCM/NoPadding", key, 96, 12, 16);
        testAEADMode("SM4/CCM/NoPadding", key, 96, 13, 16);
        testUpdateAndDofinalAEADMode("SM4/CCM/NoPadding", key, 128, 13, 15, 6);
        testUpdateAndDofinalAEADMode("SM4/CCM/NoPadding", key, 128, 13, 31, 31);
        testUpdateAndDofinalAEADMode("SM4/CCM/NoPadding", key, 128, 13, 16, 16);
        testUpdateAndDofinalAEADMode("SM4/CCM/NoPadding", key, 128, 13, 32, 18);
    }

    /**
     * test doFinal
     *
     * @param algo
     * @param key
     * @param ivLen
     * @param plainTextLen
     * @throws Exception
     */
    public static void test(String algo, Key key, int ivLen, int plainTextLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        //test dofinal without output args
        byte[] bcCipherText = bc.doFinal(plainText);
        byte[] bgmCipherText = bgm.doFinal(plainText);
        Assert.assertArrayEquals(bcCipherText, bgmCipherText);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.DECRYPT_MODE, key, ivParam);
            bgm.init(Cipher.DECRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key);
            bgm.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] bcPlainText = bc.doFinal(bcCipherText);
        byte[] bgmPlainText = bgm.doFinal(bgmCipherText);
        Assert.assertArrayEquals(bcPlainText, bgmPlainText);

        random.nextBytes(iv);
        ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        //test dofinal without output args
        byte[] pArr = new byte[plainTextLen + 20];
        random.nextBytes(pArr);
        int inputOffset = (int) (Math.random() * 20);

        int len = bc.getOutputSize(plainTextLen);
        byte[] bcres = new byte[len + 20];
        byte[] bgmres = new byte[len + 20];
        //generate outputOffset
        int ops = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcCipherLen = bc.doFinal(pArr, inputOffset, plainTextLen, bcres, ops);
        int bgmCipherLen = bgm.doFinal(pArr, inputOffset, plainTextLen, bgmres, ops);
        Assert.assertEquals(bcCipherLen, bgmCipherLen);
        Assert.assertArrayEquals(bcres, bgmres);

        if (!algo.contains("ECB")) {
            bc.init(Cipher.DECRYPT_MODE, key, ivParam);
            bgm.init(Cipher.DECRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key);
            bgm.init(Cipher.DECRYPT_MODE, key);
        }

        //generate output array
        int outputSize = bc.getOutputSize(bcCipherLen);

        byte[] bcOffsetDecrypt = new byte[20 + outputSize];
        byte[] bgmOffsetDecrypt = new byte[20 + outputSize];
        //generate outputOffset
        int offset = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcOffsetDe = bc.doFinal(bcres, ops, bcCipherLen, bcOffsetDecrypt, offset);
        int bgmOffsetDe = bgm.doFinal(bgmres, ops, bgmCipherLen, bgmOffsetDecrypt, offset);
        Assert.assertEquals(bcOffsetDe, bgmOffsetDe);
        Assert.assertArrayEquals(bcOffsetDecrypt, bgmOffsetDecrypt);
    }

    public static void testAEADMode(String algo, Key key, int tLen, int ivLen, int plainTextLen) throws Exception {
        testAEADMode(algo, key, tLen, ivLen, plainTextLen, false);
    }

    /**
     * test doFinal
     *
     * @param algo
     * @param key
     * @param tLen
     * @param ivLen
     * @param plainTextLen
     * @throws Exception
     */
    public static void testAEADMode(String algo, Key key, int tLen, int ivLen, int plainTextLen, boolean useIvParams)
            throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        int aadLen = (((int) (Math.random() * 32767)) + 1);
        byte[] aad = new byte[aadLen];
        random.nextBytes(aad);

        AlgorithmParameterSpec parameterSpec = useIvParams ?
                new IvParameterSpec(iv) : new GCMParameterSpec(tLen, iv);
        bc.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        bgm.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        bc.updateAAD(aad);
        bgm.updateAAD(aad);

        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);

        byte[] bcCipherText = bc.doFinal(plainText);
        byte[] bgmCipherText = bgm.doFinal(plainText);
        Assert.assertArrayEquals(bcCipherText, bgmCipherText);

        bc.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        bgm.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        byte[] bcPlainText = bc.doFinal(bcCipherText);
        byte[] bgmPlainText = bgm.doFinal(bgmCipherText);
        Assert.assertArrayEquals(bcPlainText, bgmPlainText);

        byte[] newIv = new byte[ivLen];
        random.nextBytes(newIv);
        while (ivLen != 0 && Arrays.equals(iv, newIv)) {
            random.nextBytes(newIv);
        }

        parameterSpec = useIvParams ? new IvParameterSpec(newIv)
                : new GCMParameterSpec(tLen, newIv);
        bc.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        bgm.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //test dofinal without output args
        byte[] pArr = new byte[plainTextLen + 20];
        random.nextBytes(pArr);
        int inputOffset = (int) (Math.random() * 20);

        int len = bc.getOutputSize(plainTextLen);
        byte[] bcres = new byte[len + 20];
        byte[] bgmres = new byte[len + 20];
        //generate outputOffset
        int ops = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcCipherLen = bc.doFinal(pArr, inputOffset, plainTextLen, bcres, ops);
        int bgmCipherLen = bgm.doFinal(pArr, inputOffset, plainTextLen, bgmres, ops);
        Assert.assertEquals(bcCipherLen, bgmCipherLen);
        Assert.assertArrayEquals(bcres, bgmres);

        bc.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        bgm.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //generate output array
        int outputSize = bc.getOutputSize(bcCipherLen);

        byte[] bcOffsetDecrypt = new byte[20 + outputSize];
        byte[] bgmOffsetDecrypt = new byte[20 + outputSize];
        //generate outputOffset
        int offset = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcOffsetDe = bc.doFinal(bcres, ops, bcCipherLen, bcOffsetDecrypt, offset);
        int bgmOffsetDe = bgm.doFinal(bgmres, ops, bgmCipherLen, bgmOffsetDecrypt, offset);
        Assert.assertEquals(bcOffsetDe, bgmOffsetDe);
        Assert.assertArrayEquals(bcOffsetDecrypt, bgmOffsetDecrypt);
    }

    /**
     * update is called to perform partial encryption(decryption)
     * and dofinal is called to end the encryption(decryption) process.
     *
     * @param algo
     * @param key
     * @param ivLen
     * @param plainTextLen
     * @param updateLen
     * @throws Exception
     */
    public static void testUpdateAndDofinal(String algo, Key key, int ivLen, int plainTextLen, int updateLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }

        byte[] bcEncryptedBytesAll = null;
        byte[] bgmEncryptedBytesAll = null;

        //partial encryption
        byte[] bcUpdate = bc.update(plainText, 0, updateLen);
        byte[] bgmUpdate = bgm.update(plainText, 0, updateLen);
        bcEncryptedBytesAll = concatBytes(bcEncryptedBytesAll, bcUpdate);
        bgmEncryptedBytesAll = concatBytes(bgmEncryptedBytesAll, bgmUpdate);

        //end the encryption
        byte[] bcdoFinalCipher = bc.doFinal(plainText, updateLen, plainTextLen - updateLen);
        byte[] bgmdoFinalCipher = bgm.doFinal(plainText, updateLen, plainTextLen - updateLen);

        //combine all encrypted results
        bcEncryptedBytesAll = concatBytes(bcEncryptedBytesAll, bcdoFinalCipher);
        bgmEncryptedBytesAll = concatBytes(bgmEncryptedBytesAll, bgmdoFinalCipher);
        Assert.assertArrayEquals(bcEncryptedBytesAll, bgmEncryptedBytesAll);

        if (!algo.contains("ECB")) {
            bc.init(Cipher.DECRYPT_MODE, key, ivParam);
            bgm.init(Cipher.DECRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key);
            bgm.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] bcDecryptedBytesAll = null;
        byte[] bgmDecryptedBytesAll = null;
        int decryptLen = (int) (Math.random() * bcEncryptedBytesAll.length);
        //partial decryption
        byte[] deBCupdate = bc.update(bcEncryptedBytesAll, 0, decryptLen);
        byte[] deBgmUpdate = bgm.update(bgmEncryptedBytesAll, 0, decryptLen);
        bcDecryptedBytesAll = concatBytes(bcDecryptedBytesAll, deBCupdate);
        bgmDecryptedBytesAll = concatBytes(bgmDecryptedBytesAll, deBgmUpdate);

        //end the decryption
        byte[] bcbytes = bc.doFinal(bcEncryptedBytesAll, decryptLen, bcEncryptedBytesAll.length - decryptLen);
        byte[] bgmbytes = bgm.doFinal(bgmEncryptedBytesAll, decryptLen, bgmEncryptedBytesAll.length - decryptLen);
        bcDecryptedBytesAll = concatBytes(bcDecryptedBytesAll, bcbytes);
        bgmDecryptedBytesAll = concatBytes(bgmDecryptedBytesAll, bgmbytes);
        Assert.assertArrayEquals(bcDecryptedBytesAll, bgmDecryptedBytesAll);

    }

    /**
     * update is called to perform partial encryption(decryption)
     * and dofinal is called to end the encryption(decryption) process.
     *
     * @param algo
     * @param key
     * @param tLen
     * @param ivLen
     * @param plainTextLen
     * @param updateLen
     */
    public static void testUpdateAndDofinalAEADMode(String algo, Key key, int tLen, int ivLen, int plainTextLen, int updateLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");

        //generate iv and tagLen
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        int aadLen = (((int) (Math.random() * 32767)) + 1);
        byte[] aad = new byte[aadLen];
        random.nextBytes(aad);
        GCMParameterSpec gcmParameterSpec = null;
        if (!algo.contains("CCM")) {
            gcmParameterSpec = new GCMParameterSpec(tLen, iv);
            bc.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //generate plainText
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);

        byte[] bcEncryptedBytesAll = null;
        byte[] bgmEncryptedBytesAll = null;

        //partial encryption
        byte[] bcUpdate = bc.update(plainText, 0, updateLen);
        byte[] bgmUpdate = bgm.update(plainText, 0, updateLen);
        bcEncryptedBytesAll = concatBytes(bcEncryptedBytesAll, bcUpdate);
        bgmEncryptedBytesAll = concatBytes(bgmEncryptedBytesAll, bgmUpdate);

        //end the encryption
        byte[] bcdoFinalCipher = bc.doFinal(plainText, updateLen, plainTextLen - updateLen);
        byte[] bgmdoFinalCipher = bgm.doFinal(plainText, updateLen, plainTextLen - updateLen);
        bcEncryptedBytesAll = concatBytes(bcEncryptedBytesAll, bcdoFinalCipher);
        bgmEncryptedBytesAll = concatBytes(bgmEncryptedBytesAll, bgmdoFinalCipher);
        Assert.assertArrayEquals(bcEncryptedBytesAll, bgmEncryptedBytesAll);

        if (!algo.contains("CCM")) {
            bc.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);

        byte[] bcDecryptedBytesAll = null;
        byte[] bgmDecryptedBytesAll = null;

        //partial decryption
        int decryptLen = (int) (Math.random() * bcEncryptedBytesAll.length);
        byte[] bcDecryptedUpdateBytes = bc.update(bcEncryptedBytesAll, 0, decryptLen);
        byte[] bgmDecryptedUpdateBytes = bgm.update(bgmEncryptedBytesAll, 0, decryptLen);
        bcDecryptedBytesAll = concatBytes(bcDecryptedBytesAll, bcDecryptedUpdateBytes);
        bgmDecryptedBytesAll = concatBytes(bgmDecryptedBytesAll, bgmDecryptedUpdateBytes);

        //end the decryption
        byte[] bcDecryptedFinalBytes = bc.doFinal(bcEncryptedBytesAll, decryptLen, bcEncryptedBytesAll.length - decryptLen);
        byte[] bgmDecryptedFinalBytes = bgm.doFinal(bgmEncryptedBytesAll, decryptLen, bcEncryptedBytesAll.length - decryptLen);
        bcDecryptedBytesAll = concatBytes(bcDecryptedBytesAll, bcDecryptedFinalBytes);
        bgmDecryptedBytesAll = concatBytes(bgmDecryptedBytesAll, bgmDecryptedFinalBytes);
        Assert.assertArrayEquals(bgmDecryptedBytesAll, bcDecryptedBytesAll);
    }

    public static byte[] concatBytes(byte[] first, byte[]... rest) {
        if (first == null) {
            first = new byte[0];
        }
        int totalLength = first.length;
        for (byte[] array : rest) {
            if (array != null) {
                totalLength += array.length;
            }
        }
        byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;
        for (byte[] array : rest) {
            if (array != null) {
                System.arraycopy(array, 0, result, offset, array.length);
                offset += array.length;
            }
        }
        return result;
    }

    public static void testInitAlgorithmParameters(String transformation, Key key, int tLen, int ivLen,
                                                   int plainTextLen) throws Exception {
        SecureRandom random = new SecureRandom();

        byte[] ivBytes = new byte[ivLen];
        random.nextBytes(ivBytes);

        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);

        Cipher bcCipher = Cipher.getInstance(transformation, "BC");
        Cipher bgmCipher = Cipher.getInstance(transformation, "BGMJCEProvider");

        AlgorithmParameterSpec parameterSpec = new GCMParameterSpec(tLen, ivBytes);
        String algorithm = getAlgorithmParametersAlgorithm(transformation);
        if (algorithm != null) {
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(algorithm);
            algorithmParameters.init(parameterSpec);
            bcCipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameters);
            bgmCipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameters);
        } else {
            bcCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            bgmCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        }
        byte[] bcEncryptedBytes = bcCipher.doFinal(plainText);
        byte[] bgmEncryptedBytes = bgmCipher.doFinal(plainText);
        Arrays.equals(bcEncryptedBytes, bgmEncryptedBytes);
    }

    private static String getAlgorithmParametersAlgorithm(String transformation) {
        if (transformation.contains("GCM")) {
            return "GCM";
        } else if (transformation.contains("CCM")) {
            return "CCM";
        }
        return null;
    }
}
