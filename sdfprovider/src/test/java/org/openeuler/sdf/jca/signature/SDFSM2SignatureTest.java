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

package org.openeuler.sdf.jca.signature;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.SDFSM2TestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

public class SDFSM2SignatureTest {
    private static final String MESSAGE = "hello world";

    private static final BGMJCEProvider bgmJCEProvider = new BGMJCEProvider();

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testSignByEncKey() throws Exception {
        int randomLoops = SDFTestUtil.generateRandomInt();
        testUpdateAndSign(true, randomLoops, MESSAGE.getBytes());
    }

    @Test
    public void testSignByEncKeyRandomly() throws Exception {
        int randomLoops = SDFTestUtil.generateRandomInt();
        byte[] data = SDFTestUtil.generateRandomBytes();
        testUpdateAndSign(true, randomLoops, data);
    }

    @Test
    public void testNoUpdate() throws Exception {
        testNoUpdate(true);
    }

    @Test
    public void testUpdateOffset() throws Exception{
        testUpdateOffset(true, new byte[0], 0, 0);
        byte[] data = SDFTestUtil.generateRandomBytes();
        int offset = 0;
        int len = 0;
        if (data.length > 0) {
            offset = SDFTestUtil.generateRandomInt(data.length);
            len = SDFTestUtil.generateRandomInt(data.length - offset);
        }
        testUpdateOffset(true, data, len, offset);
    }

    @Test
    public void testUpdateByteBuffer() throws Exception {
        // test empty data
        byte[] data = new byte[0];
        testUpdateByteBuffer(true, data, false);
        testUpdateByteBuffer(true, data, true);

        data = SDFTestUtil.generateRandomBytes();
        testUpdateByteBuffer(true, data, false);
        testUpdateByteBuffer(true, data, true);
    }

    private static void testNoUpdate(boolean isEncKey) throws Exception {
        KeyPair keyPair = SDFSM2TestUtil.generateKeyPair(isEncKey);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] data = null;
        byte[] signBytes = SDFSM2TestUtil.sign(null, privateKey, data);
        boolean verify = SDFSM2TestUtil.verify(null, publicKey, data, signBytes);
        Assert.assertTrue(verify);

        verify = SDFSM2TestUtil.verify(bgmJCEProvider, publicKey, data, signBytes);
        Assert.assertTrue(verify);
    }

    private static void testUpdateOffset(boolean isEncKey, byte[] data, int offset,int len) throws Exception {
        System.out.println("TEST data.length=" + data.length + ",len=" + len + ",offset=" + offset);
        KeyPair keyPair = SDFSM2TestUtil.generateKeyPair(isEncKey);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] signBytes = SDFSM2TestUtil.sign(null, privateKey, data, offset, len);
        boolean verify = SDFSM2TestUtil.verify(null, publicKey, data, offset, len, signBytes);
        Assert.assertTrue(verify);
        verify = SDFSM2TestUtil.verify(bgmJCEProvider, publicKey, data, offset, len, signBytes);
        Assert.assertTrue(verify);
    }

    private static void testUpdateByteBuffer(boolean isEncKey, byte[] data, boolean isDirect) throws Exception {
        KeyPair keyPair = SDFSM2TestUtil.generateKeyPair(isEncKey);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        ByteBuffer byteBuffer = newByteBuffer(data, isDirect);
        byteBuffer.mark();

        byte[] signBytes = SDFSM2TestUtil.sign(null, privateKey, byteBuffer);
        byteBuffer.reset();
        boolean verify = SDFSM2TestUtil.verify(null, publicKey, byteBuffer, signBytes);
        Assert.assertTrue(verify);

        byteBuffer.reset();
        verify = SDFSM2TestUtil.verify(bgmJCEProvider, publicKey, byteBuffer, signBytes);
        Assert.assertTrue(verify);
        byteBuffer.clear();


    }

    private static ByteBuffer newByteBuffer(byte[] data, boolean isDirect) {
        ByteBuffer byteBuffer;
        if (isDirect) {
            byteBuffer = ByteBuffer.allocateDirect(data.length);
        } else {
            byteBuffer = ByteBuffer.allocate(data.length);
        }
        byteBuffer.put(data);
        byteBuffer.flip();
        int capacity = byteBuffer.capacity();
        int limit = 0;
        if (capacity > 0) {
            limit = SDFTestUtil.generateRandomInt(capacity);
        }
        byteBuffer.limit(limit);

        int position = 0;
        if (limit > 0) {
            position = SDFTestUtil.generateRandomInt(limit);
        }
        byteBuffer.position(position);
        System.out.println("data.length= " + data.length + ",limit=" + limit + ",position=" + position);
        return byteBuffer;
    }

    private static void testUpdateAndSign(boolean isEncKey, int loops, byte[] data) throws Exception {
        KeyPair keyPair = SDFSM2TestUtil.generateKeyPair(isEncKey);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        Signature signature = SDFTestUtil.getSignature("SM3withSM2");
        signature.initSign(privateKey);
        for (int i = 0; i < loops; i++) {
            signature.update(data);
        }
        byte[] signBytes = signature.sign();

        signature = SDFTestUtil.getSignature("SM3withSM2");
        signature.initVerify(publicKey);
        for (int i = 0; i < loops; i++) {
            signature.update(data);
        }
        boolean verify = signature.verify(signBytes);
        Assert.assertTrue(verify);

        signature = SDFTestUtil.getSignature("SM3withSM2", bgmJCEProvider);
        signature.initVerify(publicKey);
        for (int i = 0; i < loops; i++) {
            signature.update(data);
        }
        verify = signature.verify(signBytes);
        Assert.assertTrue(verify);
    }
}
