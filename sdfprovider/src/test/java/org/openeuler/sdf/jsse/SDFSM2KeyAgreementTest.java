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

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestEncKeyGenUtil;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.SDFSM2GenParameterSpec;
import org.openeuler.spec.SM2KeyExchangeParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;

import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.checkKeyMaterial;
import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.generateKeyMaterial;
import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.generateMasterSecret;

/**
 * SM2KeyAgreement test
 */
public class SDFSM2KeyAgreementTest extends SDFTestCase {
    private static final Provider sdfProvider = new SDFProvider();
    private static final Provider bgmJCEProvider = new BGMJCEProvider();
    private static final Provider bgmJSSEProvider = new BGMJSSEProvider();

    private static final String CHECK_MESSAGE = "SM2 KeyAgreement test";

    private static byte[] localId;
    private static ECPublicKey localPublicKey;
    private static ECPrivateKey localPrivateKey;
    private static ECPublicKey localTempPublicKey;
    private static ECPrivateKey localTempPrivateKey;

    private static byte[] peerId;
    private static ECPublicKey peerPublicKey;
    private static ECPrivateKey peerPrivateKey;
    private static ECPublicKey peerTempPublicKey;
    private static ECPrivateKey peerTempPrivateKey;

    private static final int secretLen = 48;

    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(sdfProvider, 1);
        initParameters();
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

        localId = "1234567812345678".getBytes();
        localPublicKey = (ECPublicKey) localKeyPair.getPublic();
        localPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();
        localTempPublicKey = (ECPublicKey) localTempKeyPair.getPublic();
        localTempPrivateKey = (ECPrivateKey) localTempKeyPair.getPrivate();

        peerId = "1234567812345678".getBytes();
        peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
        peerPrivateKey = (ECPrivateKey) peerKeyPair.getPrivate();
        peerTempPublicKey = (ECPublicKey) peerTempKeyPair.getPublic();
        peerTempPrivateKey = (ECPrivateKey) peerTempKeyPair.getPrivate();
    }

    @Test
    public void testGenerateSecretBaseline() throws Exception {
        testGenerateSecretBaseline(false);
        testGenerateSecretBaseline(true);
    }

    private static byte[] testGenerateSecretBaseline(boolean isEncKey) throws Exception {
        ECPublicKey localPublicKey = SDFTestUtil.getSM2PublicKey();
        ECPrivateKey localPrivateKey = SDFTestUtil.getSM2PrivateKey(isEncKey);

        ECPublicKey localTempPublicKey = SDFTestUtil.getSM2PublicKey();
        ECPrivateKey localTempPrivateKey = SDFTestUtil.getSM2PrivateKey(isEncKey);

        ECPublicKey peerPublicKey = SDFTestUtil.getSM2PublicKey();
        ECPrivateKey peerPrivateKey = SDFTestUtil.getSM2PrivateKey(isEncKey);

        ECPublicKey peerTempPublicKey = SDFTestUtil.getSM2PublicKey();
        ECPrivateKey peerTempPrivateKey = SDFTestUtil.getSM2PrivateKey(isEncKey);


        return generateSharedSecret(localPublicKey, localPrivateKey,
                localTempPublicKey, localTempPrivateKey,
                peerPublicKey, peerPrivateKey,
                peerTempPublicKey, peerTempPrivateKey,
                isEncKey);
    }

    private static byte[] generateSharedSecret(ECPublicKey localPublicKey, ECPrivateKey localPrivateKey,
                                               ECPublicKey localTempPublicKey, ECPrivateKey localTempPrivateKey,
                                               ECPublicKey peerPublicKey, ECPrivateKey peerPrivateKey,
                                               ECPublicKey peerTempPublicKey, ECPrivateKey peerTempPrivateKey,
                                               boolean isEncKey) throws Exception {

        Provider kaProvider = isEncKey ? sdfProvider : bgmJCEProvider;

        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", kaProvider);
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] localSharedSecret = keyAgreement.generateSecret();

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, peerPublicKey, peerTempPrivateKey, peerTempPublicKey,
                localId, localTempPublicKey, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2", kaProvider);
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();

        Provider keProvider = isEncKey ? sdfProvider : bgmJSSEProvider;


        SecretKey clientPreMasterKey = new SDFSecretKeySpec(localSharedSecret,
                "GmTlsEccPremasterSecret", true);
        SecretKey serverPreMasterKey = new SDFSecretKeySpec(peerSharedSecret,
                "GmTlsEccPremasterSecret", true);
        SecretKey clientMasterKey = generateMasterSecret(clientPreMasterKey, keProvider);
        SecretKey serverMasterKey = generateMasterSecret(serverPreMasterKey, keProvider);
        System.out.println("------------------------------------------------------------");
        TlsKeyMaterialSpec clientKeyMaterial = generateKeyMaterial(clientMasterKey, keProvider);
        System.out.println("------------------------------------------------------------");
        TlsKeyMaterialSpec serverKeyMaterial = generateKeyMaterial(serverMasterKey, keProvider);
        checkKeyMaterial(clientKeyMaterial, kaProvider, serverKeyMaterial, kaProvider);

        return localSharedSecret;
    }

    @Test
    public void testGenerateSecret() throws Exception {
        generateSharedSecret(localPublicKey, localPrivateKey, localTempPublicKey, localTempPrivateKey,
                peerPublicKey, peerPrivateKey, peerTempPublicKey, peerTempPrivateKey, true);

    }

    @Test
    public void testNoneLocalPublic() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, null, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] localSharedSecret = keyAgreement.generateSecret();

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, null, peerTempPrivateKey, peerTempPublicKey,
                localId, localTempPublicKey, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();

        SecretKey clientPreMasterKey = new SDFSecretKeySpec(localSharedSecret,
                "GmTlsEccPremasterSecret", true);
        SecretKey serverPreMasterKey = new SDFSecretKeySpec(peerSharedSecret,
                "GmTlsEccPremasterSecret", true);
        SecretKey clientMasterKey = generateMasterSecret(clientPreMasterKey, sdfProvider);
        SecretKey serverMasterKey = generateMasterSecret(serverPreMasterKey, sdfProvider);
        System.out.println("------------------------------------------------------------");
        TlsKeyMaterialSpec clientKeyMaterial = generateKeyMaterial(clientMasterKey, sdfProvider);
        System.out.println("------------------------------------------------------------");
        TlsKeyMaterialSpec serverKeyMaterial = generateKeyMaterial(serverMasterKey, sdfProvider);
        checkKeyMaterial(clientKeyMaterial, sdfProvider, serverKeyMaterial, sdfProvider);

    }

    @Test(expected = InvalidKeyException.class)
    @Ignore
    public void testNormalLocalPrivateKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");

        KeyPair localKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey localPublicKey = (ECPublicKey) localKeyPair.getPublic();
        ECPrivateKey localPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();

        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
    }

    @Test(expected = InvalidKeyException.class)
    @Ignore
    public void testNormalLocalTempPrivateKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");

        KeyPair localKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey localTempPublicKey = (ECPublicKey) localKeyPair.getPublic();
        ECPrivateKey localTempPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();

        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
    }


    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.doPhase(peerPublicKey, true);
        keyAgreement.generateSecret();
    }

    @Test(expected = IllegalStateException.class)
    public void testNotDoPhase() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.generateSecret();
    }

    @Test
    public void testInit() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
    }
}
