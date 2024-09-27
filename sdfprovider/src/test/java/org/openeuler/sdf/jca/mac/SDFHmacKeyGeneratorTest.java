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
import org.junit.Ignore;
import org.junit.Test;
import org.openeuler.sdf.commons.exception.SDFErrorCode;
import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.commons.util.SDFTestUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SDFHmacKeyGeneratorTest {

    private static final int EXPECTED_DEFAULT_PLAIN_HMAC_KEY_LEN = 32;

    private static final int MIN_HMAC_KEY_SIZE = 40;
    private static final int MAX_HMAC_KEY_SIZE = 1024 * 8;
    private static final int EXPECTED_ENC_HMAC_KEY_LEN = 3584;

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    private static SDFHmacAlgorithm[] getHmacAlgorithms() {
        if (SDFTestUtil.isEnableNonSM()) {
            return SDFHmacAlgorithm.values();
        }
        return new SDFHmacAlgorithm[]{SDFHmacAlgorithm.HmacSM3};
    }

    @Test
    @Ignore
    public void testGeneratePlainKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSM3");
        SecretKey secretKey = keyGenerator.generateKey();
        assertEquals(secretKey.getEncoded().length, 32);
        assertEquals(secretKey.getAlgorithm(), "HmacSM3");
    }

    @Test
    @Ignore
    public void testAllValidKeySize() throws Exception {
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            for (int keySize = MIN_HMAC_KEY_SIZE; keySize <= MAX_HMAC_KEY_SIZE; keySize++) {
                testGenerateEncKey(hmacAlgorithm, keySize);
            }
        }
    }

    @Test
    public void testValidKeySizeRandomly() throws Exception {
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            int keySize = SDFTestUtil.generateRandomInt(MAX_HMAC_KEY_SIZE - 39) + 40;
            testGenerateEncKey(hmacAlgorithm, keySize);
        }
    }

    @Test
    public void testInvalidKeySize() throws Exception {
        SDFHmacAlgorithm[] hmacAlgorithms = getHmacAlgorithms();
        for (SDFHmacAlgorithm hmacAlgorithm : hmacAlgorithms) {
            boolean hasException = false;
            int keySize = SDFTestUtil.generateRandomInt(MIN_HMAC_KEY_SIZE);
            try {
                testGenerateEncKey(hmacAlgorithm, keySize);
            } catch (IllegalArgumentException e) {
                hasException = true;
                Assert.assertEquals("Key length must be at least 40 bits", e.getMessage());
            }
            if (!hasException) {
                throw new RuntimeException("test " + keySize + " failed, cannot be reach here");
            }

            hasException = false;
            keySize = SDFTestUtil.generateRandomInt(MAX_HMAC_KEY_SIZE) + MAX_HMAC_KEY_SIZE;
            try {
                testGenerateEncKey(hmacAlgorithm, keySize);
            } catch (Exception e) {
                hasException = true;
                Assert.assertTrue(e.getCause() instanceof SDFException);
                Assert.assertEquals(SDFErrorCode.SWR_CARD_PARAMENT_ERR.getCode(),
                        ((SDFException) e.getCause()).getErrorCode());
            }
            if (!hasException) {
                throw new RuntimeException("test " + keySize + " failed, cannot be reach here");
            }
        }
    }

    private void testGenerateEncKey(SDFHmacAlgorithm hmacAlgorithm, int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(hmacAlgorithm.algoName);
        SDFKeyGeneratorParameterSpec parameterSpec = new SDFKeyGeneratorParameterSpec(SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(), SDFTestUtil.getTestCdpId(), SDFTestUtil.getTestPin(), keySize);
        keyGenerator.init(parameterSpec);
        SecretKey secretKey = keyGenerator.generateKey();
        assertTrue(secretKey instanceof SDFSecretKeySpec);
        assertEquals(secretKey.getEncoded().length, EXPECTED_ENC_HMAC_KEY_LEN);
        assertEquals(secretKey.getAlgorithm(), hmacAlgorithm.algoName);
    }
}
