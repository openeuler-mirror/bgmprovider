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

package org.openeuler.sdf.jsse.util;

import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.SDFSM2GenParameterSpec;
import org.openeuler.spec.SM2KeyExchangeParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsMasterSecretParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class SDFSM2PreSecretUtil {

    // client random bytes
    private static final byte[] CLIENT_RANDOM_BYTES = new byte[]{
            34, -13, -128, 41, -88, 102, -99, 94, -97, 8, -7, 14, 48, -88, 14, 36,
            -81, 109, 124, 76, -43, -11, 114, 61, -100, 96, -74, 74, -13, -51, 39, 49
    };

    // server random bytes
    private static final byte[] SERVER_RANDOM_BYTES = new byte[]{
            8, -90, -57, -28, -109, 23, 75, -64, -29, -44, -99, -118, -69, -64, -28, 53,
            -83, -111, -9, -104, 69, -90, -4, -23, 61, 22, -96, 70, 113, 94, -123, 24
    };

    private static byte[] localId = "1234567812345678".getBytes();
    private static ECPublicKey localPublicKey;
    private static ECPrivateKey localPrivateKey;
    private static ECPublicKey localTempPublicKey;
    private static ECPrivateKey localTempPrivateKey;

    private static byte[] peerId = "1234567812345678".getBytes();
    private static ECPublicKey peerPublicKey;
    private static ECPrivateKey peerPrivateKey;
    private static ECPublicKey peerTempPublicKey;
    private static ECPrivateKey peerTempPrivateKey;

    private static final int secretLen = 48;

    private static SecretKey clientMasterSecret;
    private static SecretKey serverMasterSecret;
    private static SecretKey clientBlockKey;
    private static SecretKey serverBlockKey;

    static {
        try {
            initParameters();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey getClientMasterSecret() {
        return clientMasterSecret;
    }

    public static SecretKey getServerMasterSecret() {
        return serverMasterSecret;
    }

    public static SecretKey getClientBlockKey() {
        return clientBlockKey;
    }

    public static SecretKey getServerBlockKey() {
        return serverBlockKey;
    }

    private static void initParameters() throws Exception {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("SM2");
        pairGenerator.initialize(new SDFSM2GenParameterSpec(
                SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(),
                SDFTestUtil.getTestCdpId(),
                SDFTestUtil.getTestPin(),
                "sm2p256v1"));
        KeyPair localKeyPair = pairGenerator.generateKeyPair();
        KeyPair localTempKeyPair = pairGenerator.generateKeyPair();
        KeyPair peerKeyPair = pairGenerator.generateKeyPair();
        KeyPair peerTempKeyPair = pairGenerator.generateKeyPair();

        localPublicKey = (ECPublicKey) localKeyPair.getPublic();
        localPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();
        localTempPublicKey = (ECPublicKey) localTempKeyPair.getPublic();
        localTempPrivateKey = (ECPrivateKey) localTempKeyPair.getPrivate();

        peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
        peerPrivateKey = (ECPrivateKey) peerKeyPair.getPrivate();
        peerTempPublicKey = (ECPublicKey) peerTempKeyPair.getPublic();
        peerTempPrivateKey = (ECPrivateKey) peerTempKeyPair.getPrivate();

        // clientMasterSecret
        TlsMasterSecretParameterSpec cParameterSpec = createMasterSecretParameterSpec(1, 1, true);
        KeyGenerator keyGenerator1 = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator1.init(cParameterSpec);
        clientMasterSecret = keyGenerator1.generateKey();

        // serverMasterSecret
        TlsMasterSecretParameterSpec sParameterSpec = createMasterSecretParameterSpec(1, 1, false);
        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator2.init(sParameterSpec);
        serverMasterSecret = keyGenerator2.generateKey();

        // clientBlockKey;
        TlsKeyMaterialParameterSpec cTlsKeyMaterialParameterSpec = new TlsKeyMaterialParameterSpec(clientMasterSecret,
                1, 1, CLIENT_RANDOM_BYTES, SERVER_RANDOM_BYTES,
                "SM4/CBC/NoPadding", 16, 0, 16,
                32, "SM3", 32, 64);
        KeyGenerator keyGenerator3 = KeyGenerator.getInstance("GMTlsKeyMaterial");
        keyGenerator3.init(cTlsKeyMaterialParameterSpec);
        clientBlockKey = keyGenerator3.generateKey();

        // serverBlockKey;
        TlsKeyMaterialParameterSpec sTlsKeyMaterialParameterSpec = new TlsKeyMaterialParameterSpec(serverMasterSecret,
                1, 1, CLIENT_RANDOM_BYTES, SERVER_RANDOM_BYTES,
                "SM4/CBC/NoPadding", 16, 0, 16,
                32, "SM3", 32, 64);
        KeyGenerator keyGenerator4 = KeyGenerator.getInstance("GMTlsKeyMaterial");
        keyGenerator4.init(sTlsKeyMaterialParameterSpec);
        serverBlockKey = keyGenerator4.generateKey();
    }

    private static SecretKey generatePreMasterSecret(boolean isClient, String algorithm) throws Exception{
        SecretKey preSecret;
        if (isClient) {
            SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                    localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                    peerId, peerTempPublicKey, secretLen, true);
            KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
            keyAgreement.init(localPrivateKey, parameterSpec,   null);
            keyAgreement.doPhase(peerPublicKey, true);
            preSecret = keyAgreement.generateSecret(algorithm);
        } else {
            SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                    peerId, peerPublicKey, peerTempPrivateKey, peerTempPublicKey,
                    localId, localTempPublicKey, secretLen, false);
            KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
            peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
            peerKeyAgreement.doPhase(localPublicKey, true);
            preSecret = peerKeyAgreement.generateSecret(algorithm);
        }
        return preSecret;
    }

    public static TlsMasterSecretParameterSpec createMasterSecretParameterSpec(int majorVersion, int minVersion, boolean isClient) throws Exception {
        SecretKey preSecret;
        preSecret = generatePreMasterSecret(isClient,"TlsPremasterSecret");
        return new TlsMasterSecretParameterSpec(
                preSecret, majorVersion, minVersion, CLIENT_RANDOM_BYTES, SERVER_RANDOM_BYTES,
                "SM3", 32, 64);
    }
}
