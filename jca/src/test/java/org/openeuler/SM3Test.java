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

package org.openeuler;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class SM3Test {
    private static final String PLAIN_TEXT = "helloworldhello";
    private static final String ALGO = "SM3";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] EXPECTED_DIGEST = new byte[]{
            40, -103, -71, 4, -80, -49, 94, 112, 11, -75, -66, 121, 63, 80, 62, -14,
            -45, -75, -34, 66, -77, -34, -26, 26, 33, -23, 45, 52, -74, 67, -18, 118
    };

    private static final Provider bgmJCEProvider = new BGMJCEProvider();
    private static final Provider bcProvider = new BouncyCastleProvider();
    private static final int max_random_byte_len = 1024;
    private static final int testLoop = 10;

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void test() throws Exception {
        MessageDigest md = MessageDigest.getInstance(ALGO, bgmJCEProvider);
        md.update(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
        MessageDigest md2 = (MessageDigest) md.clone();
        byte[] res = md2.digest("w".getBytes(StandardCharsets.UTF_8));
        if (!Arrays.equals(res, EXPECTED_DIGEST)) {
            throw new RuntimeException("sm3 failed");
        }
    }

    @Test
    public void testDigestReuse() throws Exception {
        for (int i = 0; i < testLoop; i++) {
            byte[] randomBytes = getRandomBytes();
            // first digest
            MessageDigest md = MessageDigest.getInstance(ALGO, bgmJCEProvider);
            md.update(randomBytes);
            byte[] firstDigestBytes = md.digest();

            // second digest
            md.update(randomBytes);
            byte[] secondDigestBytes = md.digest();

            Assert.assertArrayEquals(firstDigestBytes, secondDigestBytes);
        }
    }

    @Test
    public void testReset() throws Exception {
        MessageDigest md = MessageDigest.getInstance(ALGO, bgmJCEProvider);

        // digest empty message
        byte[] emptyDigest = md.digest();
        md.reset();

        // update message and reset
        byte[] randomBytes = getRandomBytes();
        md.update(randomBytes);
        md.reset();
        byte[] digestBytes = md.digest();

        Assert.assertArrayEquals(emptyDigest, digestBytes);
    }

    @Test
    public void testUpdateDataAndDigestRandomly() throws Exception {
        for (int i = 0; i < testLoop; i++) {
            byte[] randomBytes = getRandomBytes();

            MessageDigest bgmMD = MessageDigest.getInstance(ALGO, bgmJCEProvider);
            bgmMD.update(randomBytes);
            byte[] bgmDigestBytes = bgmMD.digest();

            MessageDigest bcMD = MessageDigest.getInstance(ALGO, bcProvider);
            bcMD.update(randomBytes);
            byte[] bcDigestBytes = bcMD.digest();

            Assert.assertArrayEquals(bgmDigestBytes, bcDigestBytes);
        }
    }

    @Test
    public void testOnlyDigestDataRandomly() throws Exception {
        for (int i = 0; i < testLoop; i++) {
            byte[] randomBytes = getRandomBytes();

            MessageDigest bgmMD = MessageDigest.getInstance(ALGO, bgmJCEProvider);
            byte[] bgmDigestBytes = bgmMD.digest(randomBytes);

            MessageDigest bcMD = MessageDigest.getInstance(ALGO, bcProvider);
            byte[] bcDigestBytes = bcMD.digest(randomBytes);

            Assert.assertArrayEquals(bgmDigestBytes, bcDigestBytes);
        }
    }

    @Test
    public void testUpdateDataAndDigestDataRandomly() throws Exception {
        for (int i = 0; i < testLoop; i++) {
            byte[] randomBytes = getRandomBytes();

            MessageDigest bgmMD = MessageDigest.getInstance(ALGO, bgmJCEProvider);
            bgmMD.update(randomBytes);
            byte[] bgmDigestBytes = bgmMD.digest(randomBytes);

            MessageDigest bcMD = MessageDigest.getInstance(ALGO, bcProvider);
            bcMD.update(randomBytes);
            byte[] bcDigestBytes = bcMD.digest(randomBytes);

            Assert.assertArrayEquals(bgmDigestBytes, bcDigestBytes);
        }
    }

    @Test
    public void testClone() throws Exception {
        byte[] randomBytes = getRandomBytes();
        MessageDigest md = MessageDigest.getInstance(ALGO, bgmJCEProvider);
        md.update(randomBytes);

        // clone before digest
        MessageDigest cloneMD = (MessageDigest) md.clone();
        md.update(randomBytes);
        byte[] digestBytes = md.digest();
        cloneMD.update(randomBytes);
        byte[] cloneDigestBytes = cloneMD.digest();
        Assert.assertArrayEquals(digestBytes, cloneDigestBytes);

        // clone after digest
        cloneMD = (MessageDigest) md.clone();
        cloneMD.update(randomBytes);
        cloneMD.update(randomBytes);
        cloneDigestBytes = cloneMD.digest();
        Assert.assertArrayEquals(digestBytes, cloneDigestBytes);
    }

    private static byte[] getRandomBytes() {
        int len = RANDOM.nextInt(max_random_byte_len);
        return getRandomBytes(len);
    }

    private static byte[] getRandomBytes(int len) {
        byte[] randomBytes = new byte[len];
        RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }
}
