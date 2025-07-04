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

package org.openeuler.sdf.commons.util;

import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.config.SDFConfig;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sun.security.ec.BGECPrivateKey;

import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class SDFTestUtil {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int RANDOM_BOUND = 1024;

    private static byte[] TEST_KEK_ID;
    private static byte[] TEST_REGION_ID;
    private static byte[] TEST_CDP_ID;
    private static byte[] TEST_PIN;

    private static String SDK_CONFIG;

    private static final String DEFAULT_KEK_ID = "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-a";
    private static final String DEFAULT_REGION_ID = "RegionID1";

    // CDP ID length require: 32
    private static final String DEFAULT_CDP_ID = "cdp_id_length_need_32_0000000000";
    private static final String DEFAULT_PIN = null;

    static {
        init();
    }

    private static void initTestKeKId() {
        String kekId = System.getProperty("sdf.test.kekId", DEFAULT_KEK_ID);
        TEST_KEK_ID = kekId.getBytes();
    }

    private static void initTestRegionId() {
        String regionId = System.getProperty("sdf.test.regionId", DEFAULT_REGION_ID);
        TEST_REGION_ID = regionId.getBytes();
    }

    private static void initTestCdpId() {
        String cdpId = System.getProperty("sdf.test.cdpId", DEFAULT_CDP_ID);
        TEST_CDP_ID = cdpId.getBytes();
    }
    private static void initTestPin() {
        String pin = System.getProperty("sdf.test.pin", DEFAULT_PIN);
        TEST_PIN = (pin == null) ? null : pin.getBytes();
    }

    private static void initSDKConfig() {
        String defaultSDKConfig = getResource("sdk.config");
        SDK_CONFIG = System.getProperty("sdf.sdkConfig", defaultSDKConfig);
    }


    public static void init() {
        initTestKeKId();
        initTestRegionId();
        initTestCdpId();
        initTestPin();
        initSDKConfig();
    }

    public static String getResource(String name) {
        URL url = SDFTestUtil.class.getClassLoader().getResource(name);
        return Objects.requireNonNull(url).getPath();
    }

    public static byte[] getTestKekId() {
        return TEST_KEK_ID;
    }

    public static byte[] getTestRegionId() {
        return TEST_REGION_ID;
    }

    public static byte[] getTestCdpId() {
        return TEST_CDP_ID;
    }

    public static byte[] getTestPin() {
        return TEST_PIN;
    }

    public static String getSdkConfig() {
        return SDK_CONFIG;
    }

    public static byte[] generateRandomBytes(int randomLen) {
        byte[] bytes = new byte[randomLen];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static byte[] generateRandomBytes() {
        return generateRandomBytesByBound(RANDOM_BOUND);
    }

    public static byte[] generateRandomBytesByBound(int bound) {
        int randomLen = generateRandomInt(bound);
        return generateRandomBytes(randomLen);
    }

    public static int generateRandomInt() {
        return secureRandom.nextInt(RANDOM_BOUND);
    }

    public static int generateRandomInt(int bound) {
        return secureRandom.nextInt(bound);
    }

    public static void main(String[] args) {
        SDFTestCase sdfTestCase = new SDFTestCase();
        SDFProvider sdfProvider = new SDFProvider();
//        encSM4SecretKey(new byte[16]);

        SDFTestEncKeyGenUtil.encKey("HmacSM3", new byte[48]);
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() < 2) {
                builder.append("0");
            }
            builder.append(hex);
        }
        return builder.toString().toUpperCase();
    }

    public static Signature getSignature(String algorithm, Provider provider) throws Exception {
        Signature signature;
        if (provider != null) {
            signature = Signature.getInstance(algorithm, provider);
        } else {
            signature = Signature.getInstance(algorithm);
        }
        return signature;
    }

    public static Signature getSignature(String algorithm, String provider) throws Exception {
        Signature signature;
        if (provider != null) {
            signature = Signature.getInstance(algorithm, provider);
        } else {
            signature = Signature.getInstance(algorithm);
        }
        return signature;
    }

    public static Signature getSignature(String algorithm) throws Exception {
        return Signature.getInstance(algorithm);
    }

    public static void setKEKInfoSysPros() {
        System.setProperty("sdf.defaultKEKId", new String(SDFTestUtil.getTestKekId()));
        System.setProperty("sdf.defaultRegionId", new String(SDFTestUtil.getTestRegionId()));
        System.setProperty("sdf.defaultCdpId", new String(SDFTestUtil.getTestCdpId()));
    }

    public static boolean isEnableNonSM() {
        return SDFConfig.getInstance().isEnableNonSM();
    }

    public static ECPublicKey getSM2PublicKey() throws Exception {
        byte[] pubKeyBytes = SDFKeyTestDB.SM2_KEY_PAIR.getPubKey();
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        return (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
    }

    public static ECPrivateKey getSM2PrivateKey(boolean isEncKey) throws Exception {
        ECPublicKey publicKey = getSM2PublicKey();
        ECParameterSpec params = publicKey.getParams();
        ECPrivateKey privateKey;
        if (isEncKey) {
            BigInteger s = new BigInteger(1, SDFKeyTestDB.SM2_KEY_PAIR.getEncKey());
            privateKey = new SDFECPrivateKeyImpl(s, params, true);
        } else  {
            BigInteger s = new BigInteger(1, SDFKeyTestDB.SM2_KEY_PAIR.getPlainKey());
            privateKey = new BGECPrivateKey(s, params);
        }
        return privateKey;
    }

    public static byte[] encSM2PriKey(byte[] plainKey) {
        return SDFTestEncKeyGenUtil.encKey("SM2", plainKey);
    }

    public static byte[] encSM4SecretKey(byte[] plainKey) {
        return SDFTestEncKeyGenUtil.encKey("SM4", plainKey);
    }

}
