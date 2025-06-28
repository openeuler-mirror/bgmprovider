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

package org.openeuler.sdf.jca.mac;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.commons.util.SDFKeyTestDB;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.Security;

public class SDFHmacTest extends SDFTestCase {
    private static final Provider sdfProvider = new SDFProvider();
    private static final Provider bgmJCEProvider = new BGMJCEProvider();

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(sdfProvider, 1);
        Security.insertProviderAt(bgmJCEProvider, 2);
    }

    private static SDFHmacAlgorithm[] getHmacAlgorithms() {
        if (SDFTestUtil.isEnableNonSM()) {
            return SDFHmacAlgorithm.values();
        }
        return new SDFHmacAlgorithm[]{SDFHmacAlgorithm.HmacSM3};
    }

    @Test
    public void testGetInstance() throws Exception {
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testGetInstance(hmacAlgorithm, true);
        }
    }

    @Test
    public void testMacLen() throws Exception {
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testMacLen(hmacAlgorithm, true);
        }
    }

    @Test
    public void testEmptyPlainText() throws Exception {
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testEmptyPlainText(hmacAlgorithm, true);
        }
    }

    @Test
    public void testDoFinal() throws Exception {
        byte[] msg = SDFTestUtil.generateRandomBytes();
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testDoFinal(hmacAlgorithm, true, msg);
        }
    }

    @Test
    public void testUpdateAndDoFinal() throws Exception {
        byte[] msg = SDFTestUtil.generateRandomBytes();
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testUpdateAndDoFinal(hmacAlgorithm, true, msg);
        }
    }

    @Test
    public void testUpdateByteBuffer() throws Exception {
        byte[] msg = SDFTestUtil.generateRandomBytes();
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testUpdateByteBuffer(hmacAlgorithm, true, msg);
        }
    }

    @Test
    public void testReuse() throws Exception {
        byte[] msg = SDFTestUtil.generateRandomBytes();
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testReuse(hmacAlgorithm, true, msg);
        }
    }

    @Test
    public void testClone() throws Exception {
        byte[] msg = SDFTestUtil.generateRandomBytes();
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            System.out.println("TEST:" + hmacAlgorithm.algoName);
            testClone(hmacAlgorithm, true, msg);
        }
    }

    @Test
    public void testBaseLine() throws Exception {
        Mac sdfMac = Mac.getInstance("HmacSM3", sdfProvider);
        sdfMac.init(new SDFSecretKeySpec(SDFKeyTestDB.HMAC_SM3_KEY.getEncKey(), "HmacSM3",true));
        byte[] additional = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 22, 1, 1, 0, 16};
        byte[] bb = new byte[]{20, 0, 0, 12, -18, 19, 92, 125, 64, -109, 76, -79, -31, 21, 13, 59};
        sdfMac.update(additional);
        sdfMac.update(bb);
        byte[] sdfMacBytes = sdfMac.doFinal();

        Mac bgmMac = Mac.getInstance("HmacSM3",bgmJCEProvider);
        bgmMac.init(new SDFSecretKeySpec(SDFKeyTestDB.HMAC_SM3_KEY.getPlainKey(), "HmacSM3",false));
        bgmMac.update(additional);
        bgmMac.update(bb);
        byte[] bgmBytes = bgmMac.doFinal();
        Assert.assertArrayEquals(sdfMacBytes,bgmBytes);
    }

    private static void testGetInstance(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey) throws Exception {
        if (hmacAlgorithm.algoAliases == null) {
            return;
        }
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        for (String algoAlias : hmacAlgorithm.algoAliases) {
            Mac mac = Mac.getInstance(algoAlias, sdfProvider);
            mac.init(key);
            Assert.assertTrue(mac.getProvider() instanceof SDFProvider);
        }
    }

    private static void testMacLen(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey) throws Exception {
        byte[] randomBytes = SDFTestUtil.generateRandomBytes();
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(randomBytes);
        byte[] macBytes = mac.doFinal();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);
        Assert.assertEquals(hmacAlgorithm.macLen, macBytes.length);
    }

    private static SecretKey getKey(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(hmacAlgorithm.algoName, sdfProvider);
        // data key of hmac, should limit outKeyBitsLen in [1, 1024]
        // keySize >> 3 then << 3, the result must between [1, 1024]
        int keySize = SDFTestUtil.generateRandomInt(1016) + 8;
        if (isEncKey) {
            SDFKeyGeneratorParameterSpec parameterSpec = new SDFKeyGeneratorParameterSpec(
                    SDFTestUtil.getTestKekId(),
                    SDFTestUtil.getTestRegionId(),
                    SDFTestUtil.getTestCdpId(),
                    SDFTestUtil.getTestPin(),
                    keySize);
            keyGenerator.init(parameterSpec);
        } else {
            keyGenerator.init(keySize);
        }
        Assert.assertTrue(keyGenerator.getProvider() instanceof SDFProvider);
        return keyGenerator.generateKey();
    }

    private static void testEmptyPlainText(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey) throws Exception {
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(new byte[0]);
        byte[] macBytes = mac.doFinal();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);

        mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        byte[] newMacBytes = mac.doFinal();
        Assert.assertArrayEquals(macBytes, newMacBytes);
    }

    private static void testDoFinal(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey, byte[] msg) throws Exception {
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(msg);
        byte[] macBytes = mac.doFinal();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);

        mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        byte[] newMacBytes = mac.doFinal(msg);
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);
        Assert.assertArrayEquals(macBytes, newMacBytes);
    }

    private static void testUpdateAndDoFinal(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey, byte[] msg)
            throws Exception {
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(msg);
        mac.update(msg);
        byte[] macBytes = mac.doFinal();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);

        mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(msg);
        byte[] newMacBytes = mac.doFinal(msg);
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);
        Assert.assertArrayEquals(macBytes, newMacBytes);
    }

    private static void testUpdateByteBuffer(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey, byte[] msg)
            throws Exception {
        SecretKey key = getKey(hmacAlgorithm, isEncKey);

        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(msg);
        byte[] macBytes = mac.doFinal();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);

        // test HeapByteBuffer
        ByteBuffer heapByteBuffer = ByteBuffer.allocate(msg.length);
        heapByteBuffer.put(msg);
        heapByteBuffer.flip();
        mac.update(heapByteBuffer);
        byte[] newMacBytes = mac.doFinal();
        heapByteBuffer.clear();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);
        Assert.assertArrayEquals(macBytes, newMacBytes);

        // test DirectByteBuffer
        ByteBuffer directByteBuffer = ByteBuffer.allocate(msg.length);
        directByteBuffer.put(msg);
        directByteBuffer.flip();
        mac.update(directByteBuffer);
        newMacBytes = mac.doFinal();
        directByteBuffer.clear();
        Assert.assertTrue(mac.getProvider() instanceof SDFProvider);
        Assert.assertArrayEquals(macBytes, newMacBytes);
    }

    private static void testReuse(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey, byte[] msg)throws Exception {
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(msg);
        byte[] macBytes = mac.doFinal();

        mac.update(msg);
        byte[] newMacBytes = mac.doFinal();
        Assert.assertArrayEquals(macBytes, newMacBytes);
    }

    private static void testClone(SDFHmacAlgorithm hmacAlgorithm, boolean isEncKey, byte[] msg) throws Exception {
        SecretKey key = getKey(hmacAlgorithm, isEncKey);
        Mac mac = Mac.getInstance(hmacAlgorithm.algoName, sdfProvider);
        mac.init(key);
        mac.update(msg);

        // clone before doFinal
        Mac cloneMac = (Mac) mac.clone();
        byte[] macBytes = mac.doFinal();
        byte[] cloneMacBytes = cloneMac.doFinal();
        Assert.assertArrayEquals(macBytes, cloneMacBytes);
        Assert.assertTrue(cloneMac.getProvider() instanceof SDFProvider);

        // clone after doFinal
        cloneMac = (Mac) mac.clone();
        cloneMac.update(msg);
        cloneMacBytes = cloneMac.doFinal();
        Assert.assertArrayEquals(macBytes, cloneMacBytes);
        Assert.assertTrue(cloneMac.getProvider() instanceof SDFProvider);
    }
}
