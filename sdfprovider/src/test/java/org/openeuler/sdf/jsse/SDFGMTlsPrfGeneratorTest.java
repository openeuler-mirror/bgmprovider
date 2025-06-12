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

package org.openeuler.sdf.jsse;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestEncKeyGenUtil;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.jsse.util.SDFSM2PreSecretUtil;
import org.openeuler.sun.security.internal.spec.TlsPrfParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * GMTlsPrfGenerator test
 */
@SuppressWarnings("deprecation")
public class SDFGMTlsPrfGeneratorTest extends SDFTestCase {
    // tls label
    private static final String LABEL_CF = "client finished";
    private static final String LABEL_SF = "server finished";

    // seed
    private static final byte[] SEED = new byte[]{
            -94, 72, 103, 112, 86, -94, 88, -2, 32, -70, 109, -39, -106, 101, 110, 66,
            2, -89, -115, -19, -117, 95, 21, 68, 31, -101, 88, 115, -36, -26, -67, -56
    };

    private static final int VERIFY_DATA_LEN = 12;

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    /**
     * Test generate Key
     */
    @Test
    public void testGenerateKey() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        // client
        SecretKey cMasterSecret = SDFSM2PreSecretUtil.getClientMasterSecret();
        TlsPrfParameterSpec cTlsPrfParameterSpec = new TlsPrfParameterSpec(
                cMasterSecret, LABEL_CF, SEED, 12,
                "SM3", 32, 64);
        KeyGenerator cKeyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        cKeyGenerator.init(cTlsPrfParameterSpec);
        SecretKey cPrfSecretKey = cKeyGenerator.generateKey();
        Assert.assertEquals(VERIFY_DATA_LEN, cPrfSecretKey.getEncoded().length);


        // server
        SecretKey sMasterSecret = SDFSM2PreSecretUtil.getServerMasterSecret();
        TlsPrfParameterSpec sTlsPrfParameterSpec = new TlsPrfParameterSpec(
                sMasterSecret, LABEL_SF, SEED, 12,
                "SM3", 32, 64);
        KeyGenerator sKeyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        sKeyGenerator.init(sTlsPrfParameterSpec);
        SecretKey sPrfSecretKey = sKeyGenerator.generateKey();
        Assert.assertEquals(VERIFY_DATA_LEN, sPrfSecretKey.getEncoded().length);
    }

    @Test
    public void testLabelClientFinished() throws Exception {
        SecretKey masterSecret = generateMasterSecret();

        TlsPrfParameterSpec tlsPrfParameterSpec = new TlsPrfParameterSpec(
                masterSecret, LABEL_CF, SEED, 12,
                "SM3", 32, 64);

        KeyGenerator prfKeyGenerator= KeyGenerator.getInstance("GMTlsPrf");
        prfKeyGenerator.init(tlsPrfParameterSpec);
        SecretKey prfSecretKey = prfKeyGenerator.generateKey();
        Assert.assertEquals(VERIFY_DATA_LEN, prfSecretKey.getEncoded().length);
    }

    @Test
    public void testLabelServerFinished() throws Exception {
        SecretKey masterSecret = generateMasterSecret();
        TlsPrfParameterSpec tlsPrfParameterSpec = new TlsPrfParameterSpec(
                masterSecret, LABEL_SF, SEED, 12,
                "SM3", 32, 64);
        KeyGenerator prfKeyGenerator= KeyGenerator.getInstance("GMTlsPrf");
        prfKeyGenerator.init(tlsPrfParameterSpec);
        SecretKey prfSecretKey = prfKeyGenerator.generateKey();
        System.out.println(prfSecretKey.getEncoded().length);
    }


    @Test
    public void test() throws Exception {
        byte[] masterKeyBytes = new byte[48];
        Arrays.fill(masterKeyBytes, (byte) 0);

        SecretKey plainKey = new SDFSecretKeySpec(masterKeyBytes, "TlsMasterSecret");
        SecretKey plainFinished = prf(plainKey, new BGMJSSEProvider());

        byte[] encMasterKeyBytes = SDFTestEncKeyGenUtil.encKey("HmacSM3", masterKeyBytes);
        SecretKey encKey = new SDFSecretKeySpec(encMasterKeyBytes, "TlsMasterSecret", true);
        SecretKey encFinished = prf(encKey, new SDFProvider());

        Assert.assertArrayEquals(plainFinished.getEncoded(),encFinished.getEncoded());

    }


    private SecretKey prf(SecretKey secretKey, Provider provider) throws Exception {
        TlsPrfParameterSpec tlsPrfParameterSpec = new TlsPrfParameterSpec(
                secretKey, LABEL_SF, SEED, 12,
                "SM3", 32, 64);
        KeyGenerator prfKeyGenerator = KeyGenerator.getInstance("GMTlsPrf", provider);
        prfKeyGenerator.init(tlsPrfParameterSpec);
        SecretKey prfSecretKey = prfKeyGenerator.generateKey();
        System.out.println(prfSecretKey.getEncoded().length);
        return prfSecretKey;
    }


    private static SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSM3");
        keyGenerator.init(new SDFKeyGeneratorParameterSpec(SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(),
                SDFTestUtil.getTestCdpId(),
                SDFTestUtil.getTestPin(), keySize));
        return keyGenerator.generateKey();
    }

    private static SecretKey generateMasterSecret() throws Exception {
        return generateKey(48 * 8);
    }

    /**
     * Test not initialized before generating the key
     */
    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        keyGenerator.generateKey();
    }

    /**
     * Test invalid AlgorithmParameterSpec
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testInvalidAlgorithmParameterSpec() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsPrf");
        keyGenerator.init(new AlgorithmParameterSpec() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        });
    }
}
