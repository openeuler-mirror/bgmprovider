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

package org.openeuler.sdf.jca.digest;

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Test digest SM3/MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512
 */
public class SDFDigestTest {
    private static final Provider sdfProvider = new SDFProvider();
    private static final Provider bgmJCEProvider = new BGMJCEProvider();

    private static SDFDigestAlgorithm[] getDigestAlgorithms() {
        if (SDFTestUtil.isEnableNonSM()) {
            return SDFDigestAlgorithm.values();
        }
        return new SDFDigestAlgorithm[]{SDFDigestAlgorithm.SM3};
    }

    @Test
    public void testDigestValue() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            MessageDigest messageDigest;
            if (digestAlgorithm.isSM) {
                messageDigest = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
            } else {
                messageDigest = MessageDigest.getInstance(digestAlgorithm.algoName);
            }
            messageDigest.update(digestAlgorithm.plainText.getBytes());
            byte[] digestBytes = messageDigest.digest();
            String hexString = SDFTestUtil.toHexString(digestBytes);
            Assert.assertEquals(digestAlgorithm.algoName + " digestValue failed",
                    digestAlgorithm.digestValue, hexString);
            Assert.assertEquals(digestAlgorithm.algoName + " digestLen failed",
                    digestAlgorithm.digestLen, digestBytes.length);
        }
    }

    @Test
    public void testGetInstance() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testGetInstance(digestAlgorithm);
        }
    }

    @Test
    public void testDigestLen() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testDigestLen(digestAlgorithm);
        }
    }

    @Test
    public void testEmptyPlainText() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testEmptyPlainText(digestAlgorithm);
        }
    }

    @Test
    public void testDigestReuse() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testDigestReuse(digestAlgorithm);
        }
    }

    @Test
    public void testReset() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testReset(digestAlgorithm);
        }
    }

    @Test
    public void testUpdateDataAndDigestRandomly() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testUpdateDataAndDigestRandomly(digestAlgorithm);
        }
    }

    @Test
    public void testOnlyDigestDataRandomly() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testOnlyDigestDataRandomly(digestAlgorithm);
        }
    }

    @Test
    public void testUpdateDataAndDigestDataRandomly() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testUpdateDataAndDigestDataRandomly(digestAlgorithm);
        }
    }

    @Test
    public void testClone() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testClone(digestAlgorithm);
        }
    }

    @Test
    public void testUpdateByteBuffer() throws Exception {
        SDFDigestAlgorithm[] digestAlgorithms = getDigestAlgorithms();;
        for (SDFDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            testUpdateByteBuffer(digestAlgorithm);
        }
    }

    private void testGetInstance(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);
        if (digestAlgorithm.algoAliases == null) {
            return;
        }

        for (String algoAlias : digestAlgorithm.algoAliases) {
            MessageDigest aliasMD = MessageDigest.getInstance(algoAlias, sdfProvider);
            Assert.assertTrue(aliasMD.getProvider() instanceof SDFProvider);
        }
    }

    private void testDigestLen(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        md.update(randomBytes);
        byte[] digestBytes = md.digest();
        Assert.assertEquals(digestAlgorithm.algoName + " digestLen failed",
                digestAlgorithm.digestLen, digestBytes.length);
    }

    private void testEmptyPlainText(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        md.update(new byte[0]);
        byte[] digestBytes = md.digest();
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);
        byte[] newDigestBytes = md.digest(new byte[0]);
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);
        Assert.assertArrayEquals(digestBytes, newDigestBytes);
        md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        newDigestBytes = md.digest();
        Assert.assertArrayEquals(digestBytes, newDigestBytes);
    }

    private void testDigestReuse(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        // first digest
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        md.update(randomBytes);
        byte[] firstDigestBytes = md.digest();
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);

        // second digest
        md.update(randomBytes);
        byte[] secondDigestBytes = md.digest();
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);

        Assert.assertArrayEquals(firstDigestBytes, secondDigestBytes);
    }

    private void testReset(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);

        // digest empty message
        byte[] emptyDigest = md.digest();
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);
        md.reset();

        // update message and reset
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        md.update(randomBytes);
        md.reset();
        byte[] digestBytes = md.digest();
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);

        Assert.assertArrayEquals(emptyDigest, digestBytes);
    }

    private void testUpdateDataAndDigestRandomly(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();

        MessageDigest sdfMD = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        sdfMD.update(randomBytes);
        byte[] sdfDigestBytes = sdfMD.digest();
        Assert.assertTrue(sdfMD.getProvider() instanceof SDFProvider);

        MessageDigest othersMD = getOthersMessageDigest(digestAlgorithm);
        othersMD.update(randomBytes);
        byte[] otherDigestBytes = othersMD.digest();

        Assert.assertArrayEquals(sdfDigestBytes, otherDigestBytes);
    }

    private void testOnlyDigestDataRandomly(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();

        MessageDigest sdfMD = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        byte[] sdfDigestBytes = sdfMD.digest(randomBytes);
        Assert.assertTrue(sdfMD.getProvider() instanceof SDFProvider);

        MessageDigest othersMD = getOthersMessageDigest(digestAlgorithm);
        byte[] otherDigestBytes = othersMD.digest(randomBytes);

        Assert.assertArrayEquals(sdfDigestBytes, otherDigestBytes);
    }

    private void testUpdateDataAndDigestDataRandomly(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();

        MessageDigest sdfMD = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        sdfMD.update(randomBytes);
        byte[] sdfDigestBytes = sdfMD.digest(randomBytes);
        Assert.assertTrue(sdfMD.getProvider() instanceof SDFProvider);

        MessageDigest othersMD = getOthersMessageDigest(digestAlgorithm);
        othersMD.update(randomBytes);
        byte[] otherDigestBytes = othersMD.digest(randomBytes);

        Assert.assertArrayEquals(sdfDigestBytes, otherDigestBytes);
    }

    private void testClone(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        md.update(randomBytes);

        // clone before digest
        MessageDigest cloneMD = (MessageDigest) md.clone();
        md.update(randomBytes);
        byte[] digestBytes = md.digest();
        cloneMD.update(randomBytes);
        byte[] cloneDigestBytes = cloneMD.digest();
        Assert.assertArrayEquals(digestBytes, cloneDigestBytes);
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);
        Assert.assertTrue(cloneMD.getProvider() instanceof SDFProvider);


        // clone after digest
        cloneMD = (MessageDigest) md.clone();
        cloneMD.update(randomBytes);
        cloneMD.update(randomBytes);
        cloneDigestBytes = cloneMD.digest();
        Assert.assertArrayEquals(digestBytes, cloneDigestBytes);
        Assert.assertTrue(cloneMD.getProvider() instanceof SDFProvider);
    }

    private static MessageDigest getOthersMessageDigest(SDFDigestAlgorithm digestAlgorithm)
            throws NoSuchAlgorithmException {
        if (digestAlgorithm.isSM) {
            return MessageDigest.getInstance(digestAlgorithm.algoName, bgmJCEProvider);
        }
        return MessageDigest.getInstance(digestAlgorithm.algoName);
    }

    private void testUpdateByteBuffer(SDFDigestAlgorithm digestAlgorithm) throws Exception {
        int randomLen = SDFTestUtil.generateRandomInt();
        byte[] randomBytes = SDFTestUtil.generateRandomBytes(randomLen);

        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.algoName, sdfProvider);
        md.update(randomBytes);
        byte[] digestBytes = md.digest();
        Assert.assertTrue(md.getProvider() instanceof SDFProvider);

        // test HeapByteBuffer
        ByteBuffer heapByteBuffer = ByteBuffer.allocate(randomLen);
        heapByteBuffer.put(randomBytes);
        heapByteBuffer.flip();
        md.update(heapByteBuffer);
        byte[] newDigestBytes = md.digest();
        heapByteBuffer.clear();
        Assert.assertArrayEquals(digestAlgorithm.algoName + " failed", digestBytes, newDigestBytes);

        // test HeapByteBuffer
        ByteBuffer directByteBuffer = ByteBuffer.allocateDirect(randomLen);
        directByteBuffer.put(randomBytes);
        directByteBuffer.flip();
        md.update(directByteBuffer);
        newDigestBytes = md.digest();
        directByteBuffer.clear();
        Assert.assertArrayEquals(digestAlgorithm.algoName + " failed", digestBytes, newDigestBytes);
    }
}
